// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Boost positive virtual lag for sleep/wakeup-intensive tasks.
 */
#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)

#define NSEC_PER_USEC	1000ULL
#define NSEC_PER_MSEC	1000000ULL
#define NSEC_PER_SEC	1000000000ULL

#define NVCSW_WINDOW_NS	(100 * NSEC_PER_MSEC)
#define NVCSW_MIN_HZ	1ULL
#define NVCSW_MAX_HZ	1000ULL

struct scx_fair_nvcsw_stats {
	u64 nr_select;
	u64 nr_override;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct scx_fair_nvcsw_stats));
	__uint(max_entries, 1);
} stats SEC(".maps");

static __always_inline struct scx_fair_nvcsw_stats *get_stats(void)
{
	u32 idx = 0;

	return bpf_map_lookup_elem(&stats, &idx);
}

struct task_ctx {
	u64 nvcsw_freq;
	u64 nvcsw;
	u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct task_ctx *try_lookup_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static s64 boost_vlag(const struct fair_ext_vlag_ctx *state, u64 freq)
{
	/* Below the threshold fair's proposal is passed through as-is. */
	if (freq <= NVCSW_MIN_HZ)
		return state->vlag;

	/*
	 * Amplify the lag fair already granted, proportionally to the switch
	 * rate. The caller guarantees state->vlag >= 0 here, so the product
	 * stays positive and well below the s64 range (vlag is a ns-scale
	 * value and freq is capped at NVCSW_MAX_HZ).
	 */
	return MIN(state->vlag * (s64)freq, state->vlag_max);
}

/*
 * Refresh the task's voluntary context-switch rate, sampling over windows of
 * at least NVCSW_WINDOW_NS and normalizing longer windows to switches per
 * second.
 */
static void update_nvcsw_freq(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 delta_t, delta_nvcsw, now = bpf_ktime_get_ns();

	if (!tctx->ts) {
		tctx->nvcsw_freq = NVCSW_MIN_HZ;
		tctx->nvcsw = p->nvcsw;
		tctx->ts = now;
		return;
	}

	delta_t = now - tctx->ts;
	if (delta_t < NVCSW_WINDOW_NS)
		return;

	delta_nvcsw = p->nvcsw - tctx->nvcsw;
	tctx->nvcsw_freq = CLAMP(delta_nvcsw * NSEC_PER_SEC / delta_t,
				 NVCSW_MIN_HZ, NVCSW_MAX_HZ);
	tctx->nvcsw = p->nvcsw;
	tctx->ts = now;
}

SEC("struct_ops/fair_select_vlag")
s64 BPF_PROG(scx_fair_nvcsw_select_vlag, struct task_struct *p,
	     const struct fair_ext_vlag_ctx *state)
{
	struct scx_fair_nvcsw_stats *stats;
	struct task_ctx *tctx;
	s64 vlag;

	stats = get_stats();
	if (stats)
		stats->nr_select++;

	/* Only tasks placed on wakeup with a positive lag can be boosted. */
	if (!(state->flags & FAIR_EXT_VLAG_WAKEUP) || state->vlag < 0)
		return state->vlag;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return state->vlag;

	/*
	 * Sampling only at the points where the rate is consumed is enough:
	 * nvcsw is monotonic and the rate is normalized by the elapsed time,
	 * so skipped callbacks simply widen the measurement window.
	 */
	update_nvcsw_freq(p, tctx);

	vlag = boost_vlag(state, tctx->nvcsw_freq);
	if (stats && vlag != state->vlag)
		stats->nr_override++;

	return vlag;
}

SEC(".struct_ops")
struct sched_ext_ops scx_fair_nvcsw_ops = {
	.fair_select_vlag = (void *)scx_fair_nvcsw_select_vlag,
	.flags = SCX_OPS_FAIR,
	.name = "scx_fair_nvcsw",
};
