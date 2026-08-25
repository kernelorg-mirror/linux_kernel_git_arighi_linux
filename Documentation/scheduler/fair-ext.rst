.. SPDX-License-Identifier: GPL-2.0

===============================
BPF extensions for fair scheduling
===============================

``sched_fair_ops`` allows a BPF struct_ops program to override selected
policy decisions of the fair scheduling class without replacing it. It
requires ``CONFIG_SCHED_CLASS_FAIR_EXT``. Tasks remain in
``fair_sched_class`` and the native scheduler retains runqueue ownership.

The interface provides the following callbacks::

    struct sched_fair_ops {
            s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu,
                              u64 wake_flags);
            char name[FAIR_EXT_OPS_NAME_LEN];
    };

``select_cpu()`` runs for fair-class wakeup, fork, and exec placement while
the task's ``pi_lock`` is held. A non-negative return value requests that CPU.
A negative return value asks the kernel to use native fair CPU selection.
Invalid, offline, or disallowed CPUs also fall back to native selection.

Only one ``sched_fair_ops`` instance may be attached at a time. Detaching its
BPF link immediately restores the native fair policy.

Runtime state
=============

The current state is available from sysfs::

    # cat /sys/kernel/fair_ext/state
    enabled

The state is ``disabled`` when no extension is attached and ``enabled`` while
an extension is active. ``/sys/kernel/fair_ext/map_id`` reports the attached
struct_ops map ID, or zero when no extension is attached.

Fair placement within a CPU subset
==================================

``select_cpu()`` can delegate placement back to fair while restricting the
CPUs it may consider::

    s32 sched_fair_bpf_select_cpu(struct task_struct *p, s32 prev_cpu,
                                  u64 wake_flags,
                                  const struct cpumask *preferred_mask);

The kfunc intersects the preferred mask with the task's effective affinity
mask. Passing ``NULL`` uses the task's full effective affinity mask. The
callback can query the selected CPU with::

    s32 sched_fair_bpf_cpu_idle(s32 cpu);

Both kfuncs are available only from ``sched_fair_ops.select_cpu()`` and only
for the task passed to the active callback.

Scope
=====

Fair continues to control runqueue ordering, preemption, bandwidth accounting,
and migration mechanics. NUMA balancing, affinity changes, CPU hotplug, and
other scheduler mechanisms may move a task after ``select_cpu()`` returns.
