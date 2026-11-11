/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_pv.h"
#include "scx_pv_topo.h"
#include "scx_pvguest.bpf.skel.h"

const char help_fmt[] =
"Guest half of a paravirt scheduler pair, run scx_pvhost on the host.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-d DAX] [-n] [-f] [-g] [-F FEAT,...] [-A] [-I] [-c] [-s SLICE_US]\n"
"       [-t SECS] [-v]\n"
"\n"
"  -d DAX        devdax device shared with the host (default: /dev/dax0.0).\n"
"                Created from the first pmem region if it doesn't exist.\n"
"  -n            Report the demand but don't fold, for comparison\n"
"  -f            Fold whenever the host asks, even without steal, for comparison\n"
"  -g            Fold by the steal governor's rule alone, for comparison\n"
"  -F FEAT,...   Fold by the steal governor's rule with only these features,\n"
"                for comparison (default: all): busy, idle, follow, whole,\n"
"                quick, hold, backoff, jitter, debounce, fast\n"
"  -A            Ignore the host's preempted flags, for comparison\n"
"  -I            Ignore the host's idle CPU count, for comparison\n"
"  -c            Charge tasks the time the host preempted their vCPU too, for\n"
"                comparison\n"
"  -s SLICE_US   Slice of every task in microseconds (default: 20000)\n"
"  -t SECS       Exit after SECS seconds\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

#define ND "/sys/bus/nd/devices/"

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY), ret;

	if (fd < 0)
		return -1;
	ret = write(fd, val, strlen(val));
	close(fd);
	return ret < 0 ? -1 : 0;
}

static int rd(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	return 0;
}

/*
 * Turn the label-less namespace of the host's memory device into a devdax
 * device, like "ndctl create-namespace -f -e namespace0.0 -m devdax -M mem
 * --align 4K". -M mem keeps the memmap in guest RAM, out of the shared pages.
 */
static int setup_devdax(const char *dax)
{
	static const char * const attrs[][2] = {
		{ "namespace", "namespace0.0" },
		{ "align", "4096" },
		{ "mode", "ram" },
	};
	char seed[64], path[256], uuid[64];
	unsigned long long reg, res;
	unsigned int i;

	if (!access(dax, F_OK))
		return 0;
	wr("/sys/bus/nd/drivers/nd_pmem/unbind", "namespace0.0");
	if (rd(ND "region0/dax_seed", seed, sizeof(seed)) || !*seed) {
		fprintf(stderr, "%s doesn't exist and there is no pmem region\n", dax);
		return -1;
	}
	for (i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
		snprintf(path, sizeof(path), ND "%s/%s", seed, attrs[i][0]);
		if (wr(path, attrs[i][1])) {
			perror(path);
			return -1;
		}
	}
	snprintf(path, sizeof(path), ND "%s/uuid", seed);
	if (rd("/proc/sys/kernel/random/uuid", uuid, sizeof(uuid)) || wr(path, uuid) ||
	    wr("/sys/bus/nd/drivers/dax_pmem/bind", seed)) {
		fprintf(stderr, "enabling %s failed\n", seed);
		return -1;
	}
	/* The host imports its memfd from PV_DAX_OFF, check that the guest agrees */
	if (rd(ND "region0/resource", path, sizeof(path)))
		return -1;
	reg = strtoull(path, NULL, 16);
	if (rd("/sys/bus/dax/devices/dax0.0/resource", path, sizeof(path)))
		return -1;
	res = strtoull(path, NULL, 16);
	if (res - reg != PV_DAX_OFF) {
		fprintf(stderr, "devdax data at %#llx, the host expects %#llx\n",
			res - reg, PV_DAX_OFF);
		return -1;
	}
	return 0;
}

/*
 * Open @dax, waiting up to 5 seconds for it to work: the device node shows up
 * with the device, but opening it fails with ENXIO until the device_dax
 * driver, often a module that udev loads, binds it.
 */
static int open_devdax(const char *dax)
{
	int fd, i;

	for (i = 0; i < 100; i++) {
		fd = open(dax, O_RDWR);
		if (fd >= 0 || (errno != ENXIO && errno != ENOENT))
			break;
		usleep(50 * 1000);
	}
	return fd;
}

/* Steal time of every vCPU, in USER_HZ */
static void read_steal(unsigned long long *steal, __u32 nr_cpus)
{
	unsigned long long v[8];
	char line[256];
	FILE *f = fopen("/proc/stat", "r");
	__u32 cpu;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "cpu%u %llu %llu %llu %llu %llu %llu %llu %llu", &cpu,
			   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 9 &&
		    cpu < nr_cpus)
			steal[cpu] = v[7];
	fclose(f);
}

static bool always_fold;

/*
 * Folding stops the vCPUs of the guests from contending on the host: a vCPU
 * that waits for a host CPU, after a wakeup or a preemption, delays whatever
 * the guest waits for on it. The guest sees that wait as steal time.
 *
 * Folding costs the guest the host CPU time its extra vCPUs would have got
 * when other guests leave host CPUs idle: when its tasks block and wake a
 * lot, as with a contended lock, more vCPUs pick that time up and fewer
 * can't. That only matters while the host is saturated. On a host with idle
 * CPUs, steal comes from bursts of vCPUs colliding, and folding removes it
 * without giving up CPU time that anyone uses.
 *
 * The rule is the steal governor's (drivers/virt/steal_governor.c): every
 * second, take the steal time of all the vCPUs as a share of their time.
 * Above GOV_STEAL_HI, use one vCPU less, down to one; at or below
 * GOV_STEAL_LO, one more. -g runs it as is. The features below, all on by
 * default (-F picks some), fix where it goes wrong. idle and follow read
 * what the host writes in the shared page, which the steal governor can't
 * see; the others only need the guest's own steal:
 *
 * busy:     take steal as a share of the busy vCPUs' time, against
 *           FOLD_STEAL_HI and UNFOLD_STEAL_HI: idle vCPUs don't dilute it,
 *           and a lock-heavy guest that loses some time to steal, but would
 *           lose more CPU time folded, stays as it is.
 * idle:     halve the thresholds while more than FOLD_HOST_IDLE of the host
 *           CPUs are idle: steal then comes from vCPUs colliding, and using
 *           fewer gives up no CPU time anyone uses. And while following the
 *           host, grow back only while more than GROW_HOST_IDLE of the host
 *           CPUs are idle: folded onto its share, the guest has next to no
 *           steal whatever the load of the host, and growing onto a host with
 *           no idle CPU only brings the steal back.
 * follow:   shrink straight to the host's fair share (target_vcpus), and
 *           keep following it as it changes, all the vCPUs while the host
 *           sets no limit. Using fewer vCPUs only pays off once the guests
 *           together fit the host's CPUs, one vCPU at a time stops short.
 * whole:    grow straight back to all the vCPUs: the steal of a few more says
 *           nothing about the steal of the whole guest, which is what
 *           folding avoids.
 * quick:    judge growing back after QUICK_MS, not a full step: it often
 *           says to shrink again, and costs contention meanwhile.
 * hold:     after a change, wait HOLD_MS before growing: a folded guest
 *           has next to no steal, which says nothing about growing.
 * backoff:  shrinking again within FLAP_MS of growing means growing was
 *           wrong, as when only this guest grew and saw the others' share
 *           of the host: double the hold, up to HOLD_MAX_MS. Growing that
 *           lasts resets it.
 * jitter:   spread the hold by up to a quarter either way: guests often
 *           shrink together, from the same contention, and would grow back
 *           together.
 * debounce: shrink after two steps in a row above the threshold, or one
 *           right after growing.
 * fast:     steps of FAST_STEP_MS instead of a second.
 */
#define GOV_STEAL_HI		5.0	/* % of the time of all the vCPUs */
#define GOV_STEAL_LO		2.0
#define FOLD_STEAL_HI		30.0	/* % of the time of the busy vCPUs */
#define UNFOLD_STEAL_HI		25.0
#define FOLD_HOST_IDLE		15.0	/* % of the host CPUs */
#define GROW_HOST_IDLE		2.0
#define STEP_MS			1000
#define FAST_STEP_MS		500
#define QUICK_MS		350
#define HOLD_MS			10000
#define HOLD_MAX_MS		80000
#define FLAP_MS			3000

enum fold_feature {
	FEAT_BUSY	= 1 << 0,
	FEAT_IDLE	= 1 << 1,
	FEAT_FOLLOW	= 1 << 2,
	FEAT_WHOLE	= 1 << 3,
	FEAT_QUICK	= 1 << 4,
	FEAT_HOLD	= 1 << 5,
	FEAT_BACKOFF	= 1 << 6,
	FEAT_JITTER	= 1 << 7,
	FEAT_DEBOUNCE	= 1 << 8,
	FEAT_FAST	= 1 << 9,
};

static const char *feat_names[] = {
	"busy", "idle", "follow", "whole", "quick", "hold", "backoff", "jitter",
	"debounce", "fast",
};

#define NR_FEATS	(sizeof(feat_names) / sizeof(feat_names[0]))

static unsigned int fold_feats = (1 << NR_FEATS) - 1;

static bool has(unsigned int feat)
{
	return fold_feats & feat;
}

static int parse_feats(char *arg)
{
	unsigned int i;
	char *tok;

	fold_feats = 0;
	for (tok = strtok(arg, ",+"); tok; tok = strtok(NULL, ",+")) {
		for (i = 0; i < NR_FEATS; i++)
			if (!strcmp(tok, feat_names[i]))
				break;
		if (i == NR_FEATS)
			return -EINVAL;
		fold_feats |= 1 << i;
	}
	return 0;
}

static unsigned long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}

struct fold_sample {
	unsigned long long busy, steal;		/* USER_HZ, all vCPUs */
	unsigned long long host_idle, host_cpus;
};

static void read_sample(struct scx_pvguest *skel, struct fold_sample *t)
{
	unsigned long long v[8];
	char line[256];
	FILE *f = fopen("/proc/stat", "r");

	t->busy = t->steal = 0;
	t->host_idle = skel->bss->host_idle_sum;
	t->host_cpus = skel->bss->host_cpu_sum;
	if (!f)
		return;
	if (fgets(line, sizeof(line), f) &&
	    sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8) {
		t->busy = v[0] + v[1] + v[2] + v[5] + v[6];
		t->steal = v[7];
	}
	fclose(f);
}

/* Called every 100ms, sets the vCPUs to use in fold_limit */
static void fold_step(struct scx_pvguest *skel, struct pv_shared *shm)
{
	static unsigned long long since, step_ms, changed_at, grown_at, hold_for;
	static unsigned long long hold_ms = HOLD_MS;
	static struct fold_sample base;
	static unsigned long long epoch;
	static bool following;
	static int hi_steps;
	__u32 nr_cpus = skel->rodata->nr_cpu_ids, limit = skel->bss->fold_limit, target = 0;
	unsigned long long now = now_ms(), busy, steal, host_cpus;
	double pct, idle_pct, hi = GOV_STEAL_HI, lo = GOV_STEAL_LO;
	bool flap, shrink = false, grow = false;
	struct fold_sample t;

	/*
	 * Another host, after a migration, or the host restarted: what the
	 * guest learned about the old one doesn't hold, start over unfolded.
	 */
	if (skel->bss->host_ok && skel->bss->host_epoch != epoch) {
		if (epoch)
			printf("guest: new host registration, unfolding\n");
		epoch = skel->bss->host_epoch;
		since = changed_at = grown_at = 0;
		hold_ms = HOLD_MS;
		following = false;
		hi_steps = 0;
		skel->bss->fold_limit = nr_cpus;
		return;
	}
	if (since && now - since < step_ms)
		return;
	read_sample(skel, &t);
	busy = t.busy - base.busy;
	steal = t.steal - base.steal;
	host_cpus = t.host_cpus - base.host_cpus;
	step_ms = has(FEAT_FAST) ? FAST_STEP_MS : STEP_MS;
	if (!since) {
		since = now;
		base = t;
		return;
	}
	if (has(FEAT_BUSY)) {
		pct = busy + steal ? 100.0 * steal / (busy + steal) : 0;
		hi = FOLD_STEAL_HI;
		lo = UNFOLD_STEAL_HI;
	} else {
		pct = 100.0 * steal * 1000 / sysconf(_SC_CLK_TCK) / ((now - since) * nr_cpus);
	}
	idle_pct = host_cpus ? 100.0 * (t.host_idle - base.host_idle) / host_cpus : 0;
	if (has(FEAT_IDLE) && idle_pct > FOLD_HOST_IDLE) {
		hi /= 2;
		lo /= 2;
	}
	since = now;
	base = t;

	if (skel->bss->host_ok)
		target = PV_READ(shm->host.target_vcpus);
	if (!target || target > nr_cpus)
		target = nr_cpus;
	if (following)
		limit = target;

	flap = grown_at && now - grown_at < FLAP_MS;
	hi_steps = pct > hi ? hi_steps + 1 : 0;
	if (pct > hi && limit > 1 && !following)
		shrink = !has(FEAT_DEBOUNCE) || hi_steps >= 2 || flap;
	else if (pct <= lo && (limit < nr_cpus || following))
		grow = (!has(FEAT_HOLD) || now - changed_at >= hold_for) &&
		       (!has(FEAT_IDLE) || !following || idle_pct > GROW_HOST_IDLE);

	if (shrink) {
		if (has(FEAT_FOLLOW)) {
			following = true;
			limit = target;
		} else {
			limit--;
		}
		if (has(FEAT_BACKOFF) && flap)
			hold_ms = hold_ms * 2 < HOLD_MAX_MS ? hold_ms * 2 : HOLD_MAX_MS;
		grown_at = 0;
		hi_steps = 0;
	} else if (grow) {
		following = false;
		limit = has(FEAT_WHOLE) ? nr_cpus : limit + 1;
		grown_at = now;
		if (has(FEAT_QUICK) && has(FEAT_WHOLE))
			step_ms = QUICK_MS;
	} else if (grown_at && !flap) {
		hold_ms = HOLD_MS;
		grown_at = 0;
	}
	if (shrink || grow) {
		changed_at = now;
		hold_for = has(FEAT_JITTER) ? hold_ms * 3 / 4 + random() % (hold_ms / 2) : hold_ms;
		printf("guest: steal %.1f%%, host idle %.1f%%, %s to %u vCPUs%s\n",
		       pct, idle_pct, shrink ? "folding" : "unfolding", limit,
		       following ? ", following the host" : "");
	}
	skel->bss->fold_limit = following ? 0 : limit;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	const char *dax = "/dev/dax0.0";
	unsigned long long steal[PV_MAX_VCPUS] = {}, prev_steal[PV_MAX_VCPUS];
	struct scx_pvguest *skel;
	struct pv_shared *shm;
	struct bpf_link *link;
	size_t arena_sz;
	long timeout = 0, hz = sysconf(_SC_CLK_TCK);
	time_t start = time(NULL);
	size_t len = PV_PAGES * getpagesize();
	__s32 opt;
	unsigned int seed = time(NULL) ^ getpid();
	__u32 cpu;
	int fd;

	/* Guests booted alike share pid and clock, not the random pool */
	if (getrandom(&seed, sizeof(seed), 0) != sizeof(seed))
		seed ^= (unsigned int)(unsigned long)&seed;
	srandom(seed);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = SCX_OPS_OPEN(pvguest_ops, scx_pvguest);
	/*
	 * Longer than the host's slice: tasks that spin in user space on
	 * locks held by others waste their slices whenever a lock holder is
	 * preempted, and every slice end is a chance to preempt one.
	 */
	skel->rodata->slice_ns = 20ULL * 1000 * 1000;

	while ((opt = getopt(argc, argv, "d:nfgF:AIcs:t:vh")) != -1) {
		switch (opt) {
		case 'd':
			dax = optarg;
			break;
		case 'n':
			skel->rodata->no_fold = true;
			break;
		case 'f':
			always_fold = true;
			break;
		case 'g':
			fold_feats = 0;
			break;
		case 'F':
			if (parse_feats(optarg)) {
				fprintf(stderr, "unknown feature in %s\n", optarg);
				return 1;
			}
			break;
		case 'A':
			skel->rodata->no_preempt_hints = true;
			break;
		case 'I':
			skel->rodata->no_idle_hints = true;
			break;
		case 'c':
			skel->rodata->no_steal_clock = true;
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	SCX_BUG_ON(libbpf_num_possible_cpus() > PV_MAX_VCPUS, "more than %d vCPUs", PV_MAX_VCPUS);
	PV_SET_TOPO(skel, libbpf_num_possible_cpus());

	SCX_BUG_ON(setup_devdax(dax), "no shared memory device");
	fd = open_devdax(dax);
	SCX_BUG_ON(fd < 0, "opening %s", dax);
	shm = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	SCX_BUG_ON(shm == MAP_FAILED, "mapping %s", dax);

	SCX_OPS_LOAD(skel, pvguest_ops, scx_pvguest, uei);
	skel->bss->arena_ubase = (unsigned long)bpf_map__initial_value(skel->maps.arena, &arena_sz);
	SCX_BUG_ON(!skel->bss->arena_ubase, "arena not mapped");

	skel->bss->src = (unsigned long)shm;
	skel->bss->import_ret = 1;
	SCX_BUG_ON(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.pv_import), &opts) ||
		   skel->bss->import_ret, "importing %s: %d", dax, skel->bss->import_ret);
	printf("guest: %u vCPUs, sharing %zu bytes of %s with the host\n",
	       skel->rodata->nr_cpu_ids, len, dax);

	/* Start unfolded, fold_step() folds once it pays off; -f follows the host */
	if (!always_fold)
		skel->bss->fold_limit = skel->rodata->nr_cpu_ids;
	link = SCX_OPS_ATTACH(skel, pvguest_ops, scx_pvguest);

	read_steal(prev_steal, skel->rodata->nr_cpu_ids);
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u32 nr_cpus = skel->rodata->nr_cpu_ids, target = skel->bss->cur_target;
		/* Steal of the vCPUs in use and of the folded ones, in % of one vCPU */
		double used_steal = 0, folded_steal = 0;
		char states[PV_MAX_VCPUS + 1];
		__u32 nr_preempted = 0;
		int tick;

		for (tick = 0; tick < 10; tick++) {
			usleep(100 * 1000);
			if (!always_fold && !skel->rodata->no_fold)
				fold_step(skel, shm);
		}
		read_steal(steal, nr_cpus);
		/* The guest can read the shared pages through the dax mapping too */
		for (cpu = 0; cpu < nr_cpus; cpu++) {
			__u32 state = PV_READ(shm->gvcpu[cpu].state);
			double pct = 100.0 * (steal[cpu] - prev_steal[cpu]) / hz;

			states[cpu] = state == PV_VCPU_RUNNING ? 'R' :
				      state == PV_VCPU_FOLDED ? 'f' : '.';
			nr_preempted += PV_READ(shm->hvcpu[cpu].preempted);
			if (cpu < target)
				used_steal += pct / target;
			else
				folded_steal += pct / (nr_cpus - target);
			prev_steal[cpu] = steal[cpu];
		}
		states[cpu] = '\0';
		if (!skel->bss->host_ok) {
			printf("guest: no host scheduler, all vCPUs used, steal=%.1f%%\n",
			       used_steal);
			if (timeout && time(NULL) - start >= timeout)
				break;
			continue;
		}
		printf("guest %u: target=%u demand=%.2f vcpus=[%s] steal=%.1f%% folded_steal=%.1f%% host_preempted=%u blocked_enq=%llu\n",
		       skel->bss->guest_id, target,
		       (double)skel->bss->demand_avg / PV_DEMAND_ONE, states,
		       used_steal, folded_steal, nr_preempted,
		       (unsigned long long)skel->bss->nr_enq_blocked);
		if (timeout && time(NULL) - start >= timeout)
			break;
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_pvguest__destroy(skel);
	munmap(shm, len);
	close(fd);
	return 0;
}
