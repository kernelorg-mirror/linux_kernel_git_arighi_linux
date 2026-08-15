/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KERNEL_SCHED_EXT_FAIR_H
#define _KERNEL_SCHED_EXT_FAIR_H

struct bpf_link;
struct fair_ext_balance_ctx;
struct sched_ext_ops;
struct task_struct;

int scx_fair_reg(struct sched_ext_ops *ops, struct bpf_link *link);
void scx_fair_unreg(struct sched_ext_ops *ops, struct bpf_link *link);
int scx_fair_validate(struct sched_ext_ops *ops);
bool scx_fair_registered(void);
int __init scx_fair_init(void);

s32 sched_ext_ops__fair_select_cpu(struct task_struct *p, s32 prev_cpu,
				   u64 wake_flags);
s32 sched_ext_ops__fair_balance(const struct fair_ext_balance_ctx *ctx);

#endif /* _KERNEL_SCHED_EXT_FAIR_H */
