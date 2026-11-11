# scx pvsched

**TL;DR:** a paravirt scheduling solution. Normally the host and every
guest run two separate schedulers, each blind to what the other one
sees. With this, a sched_ext scheduler on the host and one in each guest
talk to each other through a shared BPF arena, so that both place tasks
knowing what the other side knows. To try it, run `scx_pvhost` on the
host and `scx_pvguest` in the guests, see [Running it](#running-it).

## Problem

- **Overcommit:** a host often runs more virtual CPUs than it has real
  CPUs, so the virtual CPUs take turns on the real ones.
- **Two blind schedulers:** the guest's scheduler can't see that one of
  its CPUs is currently paused by the host, so it keeps giving it work
  that then waits. The host's scheduler can't see what the guest is
  doing inside, so it can't tell which virtual CPU deserves to run.

## What exists today

- **No overcommit:** giving every virtual CPU a real CPU of its own
  avoids the problem, but wastes the CPUs that VMs leave idle.
- **Steal time:** the guest kernel measures how long its virtual CPUs
  waited for the host. Its scheduler counts that as lost capacity, so
  its load balancer slowly moves work away from virtual CPUs that lose a
  lot of time, but it can't react to a pause while it happens.
- **Lock help:** when a virtual CPU spins on a lock for too long, the
  processor traps to KVM, which runs another virtual CPU of the same VM
  instead, hopefully the lock holder. On x86, paravirt spinlocks also
  let a waiting virtual CPU sleep until the lock is released, and the
  guest can ask whether a virtual CPU is currently paused; arm64 guests
  have neither.
- **The steal governor**: inside the VM, it shrinks the set of CPUs the
  VM uses while steal time is high, shifting more scheduling decisions
  to the guest scheduler. It works from the VM's own measurements,
  without knowing how many CPUs the host could actually give it.

All of these react to the symptoms, time lost waiting or spinning, after
they show up, not to the cause: each scheduler decides without knowing
what the other one knows.

## Proposal

Let the two schedulers talk. A sched_ext scheduler on the host and one
in every guest share a few pages of memory, and each one writes there
what only it knows:

- **The host knows** which real CPUs are idle, which virtual CPUs it has
  paused right now, and how many CPUs each VM can get when they compete.
- **The guest knows** how much work it has, and which of its virtual
  CPUs are busy.

With that, each side decides with the other's information, at the moment
it decides, instead of guessing it after the fact:

- **The guest** stops queueing work behind paused virtual CPUs, stops
  waking idle virtual CPUs that would only wait for the host, and
  shrinks to exactly its fair share, but only while shrinking pays off.
- **The host** divides its CPUs between the VMs by what they actually
  need, and keeps helping virtual CPUs that spin on locks.

It covers what the existing pieces do separately (the steal governor's
shrinking, the paused-CPU check that x86 has, the lock help), on arm64
too, and from information that is exact and current rather than indirect
and late. It needs no change to QEMU or KVM: both schedulers are BPF
programs, so they can be loaded, replaced and tuned without rebooting
the host or the guests.

The kernel only gains a generic mechanism: a way for BPF arenas to
share memory with other programs, inside the same system or across a
VM boundary. Nothing in it is specific to VMs or to scheduling, and no
policy is built into the kernel: when to shrink, by how much, what to
tell the other side and what to do with what it says all live in the
BPF schedulers. Changing the policy, or trying a new one, means loading
a different BPF program on the running host and in the running guests:
no new kernel and no reboot.

## What it needs

No change to QEMU, Firecracker or KVM. Both the host and the guest
kernel need one small BPF addition, a pair of functions that let a BPF
scheduler use the pages of a shared file as its own memory
(`bpf_arena_import_memfd()` on the host, `bpf_arena_import_dax()` in the
guest). Everything else is stock.

## How they talk: a shared notebook

1. **A BPF arena:** a BPF scheduler keeps its data in a BPF arena,
   memory it uses like ordinary memory.
2. **Backed by a file:** a new BPF function lets the host scheduler
   build that arena from the pages of a file, one file per VM in
   `/run/scx-pv`.
3. **Shared with the VM:** the same file backs a small virtual memory
   device of the VM, a standard QEMU device. The host scheduler watches
   the folder and picks up every new VM by itself.
4. **Guest side:** in the VM, the device shows up as a DAX device,
   `/dev/dax0.0`, memory that a program can map directly. The guest
   scheduler maps it and puts the same pages in its own arena.
5. **Plain memory:** now both schedulers read and write the same few
   pages, a shared notebook, as their own memory. There are no messages
   or interrupts; reading it is as cheap as reading a variable (zero
   copy).

Each entry has a single writer. What the host writes, and what the guest
does with it:

| Host writes | Updated | Guest uses it to |
|---|---|---|
| Fair share: how many virtual CPUs the VM may use (or "all") | every 1ms | fold to that many CPUs |
| How many of the host's CPUs are idle right now | every 1ms | not wake sleeping virtual CPUs when the host is full; fold earlier when it has room |
| Per virtual CPU: "paused by me right now" | when the host pauses or resumes the virtual CPU | not queue work behind a paused virtual CPU, and take work stuck there |
| Per virtual CPU: total time spent waiting for a real CPU (steal) | when the virtual CPU runs again | not charge that time to the task that was running |
| Heartbeat | every 1ms | ignore the notebook while it stops moving |

What the guest writes, and what the host does with it:

| Guest writes | Updated | Host uses it to |
|---|---|---|
| How busy it is: average number of runnable tasks | every few ms | compute every VM's fair share |
| How many virtual CPUs it has | at start | cap that (it also counts the VM's virtual CPU threads itself, and trusts the lower number) |
| Per virtual CPU: running, idle or folded | at every change | give folded virtual CPUs, which only wake for housekeeping, shorter turns |
| Heartbeat, and "my scheduler is running" | every few ms | leave the VM out of the fair shares while it stops moving |

Both sides also write a few counters for monitoring (how many CPUs and
VMs share the host, how many virtual CPUs are folded) that the other side
doesn't act on.

The heartbeats let either side start, stop or crash independently. If
the host goes quiet, the guest simply behaves like a normal VM.

Every time the host picks up a VM, it writes a new random number, the
epoch, at the top of the notebook. A guest that sees the epoch change
knows it's talking to a new host, or to a restarted one: it writes its
own entries again and forgets what it learned about when to fold.

That's what makes live migration work. The destination QEMU maps its
own file in the destination's `/run/scx-pv`, so the host there picks
the VM up as a new one. The migration then either copies the notebook
from the source, overwriting the destination host's entries with the
source host's, or doesn't copy it (QEMU's `x-ignore-shared`), leaving
the guest's entries empty. In the first case the host notices that its
epoch was overwritten and writes its entries back; in the second the
guest sees a new epoch and fills its entries in again. Either way, the
guest is back under the new host's fair share within a second or two.
If the destination runs no host scheduler, the heartbeat stops and the
guest behaves like a normal VM. Both cases were tested by migrating a
VM between two QEMU processes on the same host, each with its own file.

Not everything goes through the notebook. When a virtual CPU spins on a
lock, KVM tells the host directly, as it does for any VM; and the guest
measures its own steal for folding from the kernel's usual counters,
the same way the steal governor does.

## What the host does with it

- **Fair shares:** every millisecond, it divides its real CPUs between
  the VMs by how busy each one says it is, and tells each VM how many
  virtual CPUs it can use. CPUs that don't divide evenly go to
  different VMs every second. A VM can't claim more virtual CPUs than the
  host counts in it.
- **Fair shares for VMs without the paravirt scheduler:** a VM that
  doesn't run it counts in the division too, by how many of its virtual
  CPUs are busy, and since it doesn't shrink on its own, the host holds
  it to its share: at most that many of its virtual CPUs run at once,
  the others wait for their turn. A real CPU that nothing else wants
  still goes to one of them for a short time, and is taken back as soon
  as another task needs it, so the host doesn't sit idle while a VM
  waits. Without this, the VMs that shrink would give up CPU time to
  the ones that don't (`-T` turns it off).
- **Lock spinning:** a virtual CPU that spins on a lock exits to KVM,
  which asks the host to run another virtual CPU of the same VM instead,
  likely the one holding the lock. The host scheduler honors that
  request and runs that virtual CPU first. This matters most for VMs
  without paravirt spinlocks, like arm64 ones: on x86, a virtual CPU
  waiting for a lock whose holder is paused can go to sleep until the
  lock is free, but on arm64 it keeps spinning, burning its time on the
  real CPU while the holder waits for one. Without this help, arm64 VMs
  nearly stall under lock contention.

## What the guest does with it

- **Paused CPUs:** it doesn't put work behind a virtual CPU the host has
  paused; it sends that work to one that's actually running.
- **Host full:** when the host has no idle CPU, it doesn't wake up a
  sleeping virtual CPU, which would only wait in line; it gives the work
  to one that's already running.
- **Folding:** it can voluntarily shrink to its fair share of virtual
  CPUs and park the rest. The virtual CPUs then stop fighting each other
  for real CPUs.
- **Fair charging:** a task isn't charged for the time its virtual CPU
  waited for a real CPU. The kernel can do this too, but only with
  CONFIG_PARAVIRT_TIME_ACCOUNTING, which guest kernels often leave off;
  the host's count works with any guest kernel.

## Adaptive folding: when to shrink

Folding is great when every virtual CPU is busy all the time, because
they fight constantly. It's bad when the tasks mostly wait on each other
(for example on a lock): the parked CPUs weren't costing anything, and
shrinking just squeezes the waiting tasks onto fewer CPUs.

### What the steal governor does

The guest starts from the steal governor's rule: every second, if the
virtual CPUs lose more than 5% of their time to steal (time they wanted
to run but the host was running someone else), use one CPU less; at 2%
or below, use one more. The guest sees only its own steal, so this is
all it can go by. `scx_pvguest -g` runs this rule alone.

### What the guest can do better on its own

These changes need nothing from the host. They only change what the
rule looks at and how fast it moves, so the steal governor could adopt
them too:

1. **Count steal against the busy CPUs only,** and fold only above 30%,
   unfold at 25% or below. Idle CPUs don't water the number down, and a
   lock-heavy workload, which usually loses less than 30% on a full
   host, stays unfolded: folding it would give up CPU time it uses.
2. **Unfold all the way, and check quickly.** A folded VM has almost no
   steal, which says nothing about whether unfolding would pay off. So
   after 10 seconds it unfolds completely and checks again a third of a
   second later, with the fight back at full strength. If it's still
   there, it folds back right away.
3. **Unfold less often when unfolding turns out wrong.** If a VM folds
   back within 3 seconds, it waits longer before the next try: 20
   seconds, then 40, then 80 at most. An unfold that lasts brings it
   back to 10 seconds. VMs also try at slightly different times, since
   they usually fold together and would otherwise unfold together.
4. **Don't react to a blip:** check twice a second and fold only after
   two checks in a row say so (one, right after unfolding).

### What the shared notebook adds

Steal tells a guest that it's fighting, but not with whom or how much
room there is. The host knows both and writes them in the notebook,
which the steal governor has no way to read:

5. **Fold straight to the host's fair share** and keep following it as
   it changes: all the CPUs whenever the host has room for every VM.
   Shrinking one CPU at a time stops too early: the fight only ends
   once the VMs together fit the host, and a guest can't work out from
   its own steal how many CPUs that is.
6. **Fold earlier when the host has room,** at half the thresholds
   while more than 15% of the host's CPUs are idle. Then the waits come
   from bursts of virtual CPUs waking up at the same time (a build does
   this all the time), and folding costs nothing. From inside the guest
   this steal looks the same as steal from a full host.

Each of these is a separate switch (`scx_pvguest -F`), so you can
measure what it adds.

## How to test it

### Requirements

- **Kernel, on the host and in the VMs:** the branch with
  `bpf_arena_import_memfd()` and `bpf_arena_import_dax()`, with
  sched_ext enabled (`CONFIG_SCHED_CLASS_EXT=y`,
  `CONFIG_DEBUG_INFO_BTF=y`). The same kernel can run on both sides.
- **The VM kernel also needs** the DAX device: `CONFIG_DEV_DAX_PMEM` and
  `CONFIG_NVDIMM_DAX`, plus `CONFIG_VIRTIO_PMEM` on x86 or
  `CONFIG_OF_PMEM` on arm64.
- **QEMU:** any recent version on x86. On arm64, QEMU 10.2 or later, the
  first one that supports the NVDIMM device there.
- **To build the schedulers:** a recent clang (clang 18 is too old, we
  use clang 22).

Build both schedulers from the kernel tree:

```
make -C tools/sched_ext CLANG=clang-22 LLVM_STRIP=llvm-strip-22 \
     scx_pvhost scx_pvguest
```

### Running it

1. **On the host,** start the host scheduler. `-C` limits the VMs to a
   set of host CPUs, an easy way to set up overcommit; `-u` lets a
   regular user start the VMs:

   ```
   sudo scx_pvhost -C 8-15 -u $USER
   ```

2. **Start each VM** with a small memory device backed by its own file
   in `/run/scx-pv`, which QEMU creates (`$f` below, for example
   `/run/scx-pv/vm0`). On arm64, add to the QEMU command line:

   ```
   -machine nvdimm=on -m 2G,slots=2,maxmem=4G \
   -object memory-backend-file,id=pv,mem-path=$f,size=16M,share=on \
   -device nvdimm,memdev=pv
   ```

   On x86, use `-device virtio-pmem-pci,memdev=pv` instead, without
   `-machine nvdimm=on`. The host scheduler picks up the VM by itself.

3. **In each VM,** start the guest scheduler, which sets up and finds
   the DAX device by itself:

   ```
   scx_pvguest
   ```

4. **When a VM is gone,** remove its file (`rm /run/scx-pv/vm0`):
   neither QEMU nor the host scheduler does.

Either scheduler can be stopped or restarted at any time: without the
host scheduler, or without its own, a VM simply behaves like a normal
VM.

### With virtme-ng

Two 8-CPU VMs on 8 host CPUs (2x overcommit) on arm64, each running the
guest scheduler and a CPU-bound workload. In one terminal:

```
sudo scx_pvhost -C 8-15 -u $USER
```

In another one:

```
for vm in 0 1; do
    f=/run/scx-pv/vm$vm
    vng -r --cpus 8 --user root --qemu-opts="-machine nvdimm=on \
    -m 2G,slots=2,maxmem=4G \
    -object memory-backend-file,id=pv,mem-path=$f,size=16M,share=on \
    -device nvdimm,memdev=pv" -- "scx_pvguest & stress-ng --cpu 8" &
done
wait
rm /run/scx-pv/vm0 /run/scx-pv/vm1
```

## Results

On an 8-CPU slice of an NVIDIA Vera host (arm64, two sockets of 88
cores, 352 CPUs), with 8-CPU VMs on QEMU 10.2 or Firecracker 1.17,
confined to those 8 host CPUs. The VMs boot from a read-only disk image,
with a second disk for the results: nothing is shared with the host's
files. Three setups:

- **EEVDF:** stock host and stock VMs, both on the kernel's EEVDF.
- **steal gov:** the same, with the steal governor in the VMs.
- **scx_pvguest:** scx_pvhost on the host and scx_pvguest in the VMs.

hackbench is message passing, mutex is lock-heavy work (pthread mutex),
schbench and nginx are request serving (nginx serves a small page to wrk
in the same VM; p99 is how long the slowest 1% of requests take), lower
is better, except requests per second (rps). vs EEVDF and vs steal are
how much faster scx_pvguest is than each of them (for rps, how many more
requests it serves), from the unrounded means: +100% is twice as fast, a
negative value means slower. vCPU steal is the share of the busy time of
the virtual CPUs lost waiting for a real CPU, from the lowest to the
highest over all workloads, VMs and phases.

### 2x overcommit

Two VMs, 16 virtual CPUs for 8 real ones. Phases of 30 seconds (5
minutes for the kernel build). Each number is the average of the two
VMs' own means:

```
  workload         EEVDF  steal gov  scx_pvguest  vs EEVDF  vs steal
  --------------  ------  ---------  -----------  --------  --------
  hackbench        4.45s      2.59s        1.49s     +198%      +74%
  compute          2.47s      2.59s        2.60s       -5%       +0%
  mutex            0.70s      0.88s        0.63s      +11%      +39%
  kernel build    46.59s     37.24s       35.42s      +32%       +5%
  schbench p99    0.144s     1.146s       0.075s      +93%    +1434%
  schbench rps       173         76          320      +85%     +322%
  nginx p99       7.86ms     9.62ms       4.26ms      +85%     +126%
  nginx rps         126k       201k         251k      +98%      +25%
  vCPU steal      44-52%     10-30%        2-23%
```

- **The steal governor** (the existing approach, inside the VM only)
  shrinks the VM whenever its CPUs are contended. That helps message
  passing and the kernel build, 1.7x and 1.25x as fast as stock VMs,
  but hurts the mutex (26% slower) and schbench, where tasks spin on
  locks: less than half the requests, with a tail 8x as long. With
  nginx it serves 1.6x the requests of stock VMs, with a longer tail.
- **The paravirt scheduler** shrinks only while that seems to pay off.
  It's 3x as fast as stock VMs on hackbench and 1.3x on the kernel
  build, and serves 1.85x the schbench requests and twice the nginx
  ones, with about half the tail. It's ahead of the steal governor on
  every workload but compute, where they tie.
- **Compute:** 5% behind stock VMs, where it shrinks and they don't.
- **Request serving:** schbench's workers spin on locks in user space.
  Pausing a task while it holds a lock leaves the others spinning on it,
  so the VM's scheduler lets each task run for up to 20ms before
  switching to another.

The same with Firecracker:

```
  workload         EEVDF  steal gov  scx_pvguest  vs EEVDF  vs steal
  --------------  ------  ---------  -----------  --------  --------
  hackbench        4.17s      2.55s        1.47s     +183%      +73%
  compute          2.47s      2.55s        2.60s       -5%       -2%
  mutex            0.73s      0.86s        0.73s       +1%      +19%
  kernel build    53.17s     37.57s       36.71s      +45%       +2%
  schbench p99    0.145s     1.045s       0.081s      +79%    +1192%
  schbench rps       172         77          321      +87%     +316%
  nginx p99       7.77ms     9.19ms       5.28ms      +47%      +74%
  nginx rps         121k       202k         241k     +100%      +19%
  vCPU steal      44-51%     10-26%        3-19%
```

- **Same picture as with QEMU:** 2.8x as fast as stock VMs on
  hackbench and 1.45x on the kernel build, 1.9x the schbench requests
  and twice the nginx ones, with a shorter tail. Ahead of the steal
  governor on every workload but compute, 2% behind.

### 6x overcommit

Six VMs, 48 virtual CPUs for 8 real ones. Phases of 60 seconds, and a
single 15-minute phase for the kernel build, where stock VMs finished
only 4 builds each. With six VMs some finish many more runs than others,
so each number is the average of the six VMs' own means:

```
  workload          EEVDF  steal gov  scx_pvguest  vs EEVDF  vs steal
  --------------  -------  ---------  -----------  --------  --------
  hackbench         9.19s      6.34s        4.25s     +116%      +49%
  compute           7.45s      7.85s        7.54s       -1%       +4%
  mutex             0.68s      0.59s        0.55s      +24%       +8%
  kernel build    190.64s    112.65s      103.76s      +84%       +9%
  schbench p99      1.32s      5.00s        0.85s      +55%     +487%
  schbench rps         58         16          110      +89%     +591%
  nginx p99       49.00ms    16.70ms      12.83ms     +282%      +30%
  nginx rps           77k        90k         128k      +67%      +41%
  vCPU steal       79-88%     23-48%        6-43%
```

- **Stock VMs lose four fifths of their time to steal:** the kernel
  build takes 1.8x as long as with the paravirt scheduler, hackbench
  2.2x.
- **The steal governor helps more here:** with six VMs contending,
  shrinking pays off even for the mutex, 15% faster than stock VMs, and
  for nginx, 18% more requests with a third of the tail. But schbench
  collapses to a quarter of their requests, with a 5-second tail.
- **The paravirt scheduler is ahead of the steal governor on every
  workload,** by 4-9%, except hackbench, 1.5x as fast, and request
  serving: 7x the schbench requests, 41% more nginx ones. Compute is 1%
  behind stock VMs.
- **Even between VMs:** the six paravirt VMs ran the kernel build in
  103-104s each, with the steal governor in 88-134s, depending on how
  far each one shrank. 8 CPUs don't divide by 6 VMs, so the 2 CPUs left
  over go to different VMs every second: the same 2 VMs would otherwise
  always run faster than the others.

The same with Firecracker, the kernel build again in a single 15-minute
phase:

```
  workload          EEVDF  steal gov  scx_pvguest  vs EEVDF  vs steal
  --------------  -------  ---------  -----------  --------  --------
  hackbench         9.51s      6.12s        4.10s     +132%      +49%
  compute           7.42s      7.87s        7.63s       -3%       +3%
  mutex             0.65s      0.58s        0.56s      +16%       +4%
  kernel build    205.70s    117.65s      107.59s      +91%       +9%
  schbench p99      1.39s      4.97s        1.23s      +13%     +304%
  schbench rps         58         15          106      +83%     +599%
  nginx p99       48.00ms    16.84ms      14.94ms     +221%      +13%
  nginx rps           73k        86k         119k      +63%      +39%
  vCPU steal       78-87%     23-44%        7-47%
```

- **Same picture as with QEMU:** ahead of the steal governor on every
  workload, by 3-9% and 1.5x on hackbench, with 7x the schbench
  requests and 39% more nginx ones, and ahead of stock VMs on every
  workload but compute, 3% behind.
- **schbench tail:** only 11% shorter than stock VMs' (35% with QEMU),
  although it serves 83% more requests.
- **Compute wasn't split evenly:** the paravirt VMs ran it in 7.2-8.4s.

### Guests without scx_pvguest

A guest doesn't have to run scx_pvguest. scx_pvhost schedules a VM
that doesn't register as an ordinary VM: its virtual CPUs are not
folded, and it keeps all of them. It can't take more than its share,
though: while other VMs want CPU, scx_pvhost holds each VM to its fair
share of the host CPUs. A VM can still use host CPUs that nobody else is
using. `-T` turns this off.

The cost of holding a stock VM to its share is wakeup latency: only
part of its virtual CPUs run at once, so a virtual CPU woken by another
one may wait for its turn. Running scx_pvguest avoids it: the VM shrinks
to its share by itself, onto virtual CPUs that keep running. That's by
design: a VM gets the best latency by cooperating with the host.

## TODO

- **Keep the rest of EEVDF:** scx_pvguest is a scheduler of its own, so
  using it changes how every task in the guest is scheduled, not only
  how many CPUs the guest uses. scx_eevdf, and its Rust version
  scx_reevdf, reimplement the kernel's fair scheduler in sched_ext.
  Adding folding and the shared notebook to them would give a guest
  EEVDF with the paravirt features on top, and make the comparison
  direct: scx_eevdf against the in-kernel EEVDF, the steal governor's
  rule on scx_eevdf against the in-kernel steal governor, and the
  notebook's features against the same base.
- **A fully fair host:** the host scheduler is fair between virtual
  CPUs, not between VMs:
  - **Cooperation is trusted, not checked:** a VM whose scheduler
    answers the host is expected to shrink to its share by itself, and
    isn't held to it. One that answers but never shrinks keeps all its
    virtual CPUs running and takes the CPU time that the honest VMs
    give up. A VM held to its share also keeps the idle host CPUs it
    borrows: a stock VM next to two paravirt VMs gets 40% of the host
    instead of 33%. A host scheduler fair between VMs first, and then
    between the virtual CPUs of each VM, would fix both: ignoring the
    share would gain nothing, and borrowed time would be paid back.
  - **Equal shares only:** every VM gets the same share, whatever its
    number of virtual CPUs; a host with VMs of different sizes would
    want shares by size, or by a weight it sets.
- **Confidential VMs:** in a confidential VM (Intel TDX, AMD SEV-SNP,
  Arm CCA), the host can't read the guest's memory, including the shared
  notebook as it is set up today. This doesn't go against the idea of
  confidential computing: these VMs already share some memory with the
  host on purpose, for example for their virtual devices, and the
  notebook holds nothing secret. The guest would have to mark the
  notebook's pages as shared with the host, and the BPF function that
  maps them into the scheduler's memory would have to keep them shared.
  The guest would also have to treat everything the host writes as
  untrusted, and publish as little about itself as it can, since what it
  writes reveals what it is doing.
