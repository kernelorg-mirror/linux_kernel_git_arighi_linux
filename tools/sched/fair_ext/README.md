# Fair scheduler extension examples

These policies demonstrate the independent `sched_fair_ops` BPF struct_ops
interface. Build them from the kernel source tree with:

```shell
make -C tools/sched/fair_ext
```

The resulting binaries are written to `build/bin/`.

## fair_ext_flat_idle

Track idle CPUs entirely in BPF using a single flat BPF cpumask:

```shell
sudo build/bin/fair_ext_flat_idle
```

The policy initializes its mask from the attachment-time `update_idle()`
notifications and keeps it current from subsequent idle transitions.
`select_cpu()` chooses from the intersection of that mask and the task's
effective affinity, then atomically clears the selected CPU to reserve it
against concurrent placements. It intentionally ignores cache and NUMA
topology. If no tracked idle CPU is available, placement falls back to native
fair scheduling.

## fair_ext_tiered

Treat a Linux CPU-list expression as a soft placement preference:

```shell
sudo build/bin/fair_ext_tiered -c 0-3,8
```

The policy delegates topology and load decisions to native fair placement
within the preferred subset. If the selected CPU is busy, placement falls back
to the task's full effective affinity mask. Its `balance()` callback prevents
non-preferred CPUs from pulling work while the preferred mask has idle capacity.

Pass a cgroup v2 path to limit the preference to tasks in that cgroup subtree:

```shell
sudo build/bin/fair_ext_tiered -c 0-3,8 -g /sys/fs/cgroup/workload
```

In this mode, `can_migrate_task()` filters matching migration candidates while
native fair balancing remains unchanged for other tasks.

## fair_ext_noop

Measure extension callback overhead while retaining native fair behavior:

```shell
sudo build/bin/fair_ext_noop
```

`select_cpu()` requests native fallback, `balance()` continues native balancing,
and `can_migrate_task()` accepts every migration candidate.
