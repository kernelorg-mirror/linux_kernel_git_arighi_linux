.. _sched-ext:

==========================
Extensible Scheduler Class
==========================

sched_ext is a scheduler class whose behavior can be defined by a set of BPF
programs - the BPF scheduler.

* sched_ext exports a full scheduling interface so that any scheduling
  algorithm can be implemented on top.

* The BPF scheduler can group CPUs however it sees fit and schedule them
  together, as tasks aren't tied to specific CPUs at the time of wakeup.

* The BPF scheduler can be turned on and off dynamically anytime.

* The system integrity is maintained no matter what the BPF scheduler does.
  The default scheduling behavior is restored anytime an error is detected,
  a runnable task stalls, or on invoking the SysRq key sequence
  `SysRq-S`.

* When the BPF scheduler triggers an error, debug information is dumped to
  aid debugging. The debug dump is passed to and printed out by the
  scheduler binary. The debug dump can also be accessed through the
  `sched_ext_dump` tracepoint. The SysRq key sequence `SysRq-D`
  triggers a debug dump. This doesn't terminate the BPF scheduler and can
  only be read through the tracepoint.

Switching to and from sched_ext
===============================

``CONFIG_SCHED_CLASS_EXT`` is the config option to enable sched_ext and
``tools/sched_ext`` contains the example schedulers. The following config
options should be enabled to use sched_ext:

.. code-block:: none

    CONFIG_BPF=y
    CONFIG_SCHED_CLASS_EXT=y
    CONFIG_BPF_SYSCALL=y
    CONFIG_BPF_JIT=y
    CONFIG_DEBUG_INFO_BTF=y
    CONFIG_BPF_JIT_ALWAYS_ON=y
    CONFIG_BPF_JIT_DEFAULT_ON=y

sched_ext is used only when the BPF scheduler is loaded and running.

If a task explicitly sets its scheduling policy to ``SCHED_EXT``, it will be
treated as ``SCHED_NORMAL`` and scheduled by the fair-class scheduler until the
BPF scheduler is loaded.

When the BPF scheduler is loaded and ``SCX_OPS_SWITCH_PARTIAL`` is not set
in ``ops->flags``, all ``SCHED_NORMAL``, ``SCHED_BATCH``, ``SCHED_IDLE``, and
``SCHED_EXT`` tasks are scheduled by sched_ext.

However, when the BPF scheduler is loaded and ``SCX_OPS_SWITCH_PARTIAL`` is
set in ``ops->flags``, only tasks with the ``SCHED_EXT`` policy are scheduled
by sched_ext, while tasks with ``SCHED_NORMAL``, ``SCHED_BATCH`` and
``SCHED_IDLE`` policies are scheduled by the fair-class scheduler which has
higher sched_class precedence than ``SCHED_EXT``.

Terminating the sched_ext scheduler program, triggering `SysRq-S`, or
detection of any internal error including stalled runnable tasks aborts the
BPF scheduler and reverts all tasks back to the fair-class scheduler.

.. code-block:: none

    # make -j16 -C tools/sched_ext
    # tools/sched_ext/build/bin/scx_simple
    local=0 global=3
    local=5 global=24
    local=9 global=44
    local=13 global=56
    local=17 global=72
    ^CEXIT: BPF scheduler unregistered

The current status of the BPF scheduler can be determined as follows:

.. code-block:: none

    # cat /sys/kernel/sched_ext/state
    enabled
    # cat /sys/kernel/sched_ext/root/ops
    simple

You can check if any BPF scheduler has ever been loaded since boot by examining
this monotonically incrementing counter (a value of zero indicates that no BPF
scheduler has been loaded):

.. code-block:: none

    # cat /sys/kernel/sched_ext/enable_seq
    1

Each running scheduler exposes an ``events`` file under its sysfs kobject
(``/sys/kernel/sched_ext/root/events`` for the root scheduler) that tracks
diagnostic counters. Each counter occupies one ``name value`` line:

.. code-block:: none

    # cat /sys/kernel/sched_ext/root/events
    SCX_EV_SELECT_CPU_FALLBACK 0
    SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE 0
    SCX_EV_DISPATCH_KEEP_LAST 123
    SCX_EV_ENQ_SKIP_EXITING 0
    SCX_EV_ENQ_SKIP_MIGRATION_DISABLED 0
    SCX_EV_REENQ_IMMED 0
    SCX_EV_REENQ_REPEAT 0
    SCX_EV_REFILL_SLICE_DFL 456789
    SCX_EV_BYPASS_DURATION 0
    SCX_EV_BYPASS_DISPATCH 0
    SCX_EV_BYPASS_ACTIVATE 0
    SCX_EV_INSERT_NOT_OWNED 0
    SCX_EV_SUB_BYPASS_DISPATCH 0

The counters are described in ``kernel/sched/ext/internal.h``; briefly:

* ``SCX_EV_SELECT_CPU_FALLBACK``: ops.select_cpu() returned a CPU unusable by
  the task and the core scheduler silently picked a fallback CPU.
* ``SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE``: a local-DSQ dispatch was redirected
  to the global DSQ because the target CPU went offline.
* ``SCX_EV_DISPATCH_KEEP_LAST``: a task continued running because no other
  task was available (only when ``SCX_OPS_ENQ_LAST`` is not set).
* ``SCX_EV_ENQ_SKIP_EXITING``: an exiting task was dispatched to the local DSQ
  directly, bypassing ops.enqueue() (only when ``SCX_OPS_ENQ_EXITING`` is not set).
* ``SCX_EV_ENQ_SKIP_MIGRATION_DISABLED``: a migration-disabled task was
  dispatched to its local DSQ directly (only when
  ``SCX_OPS_ENQ_MIGRATION_DISABLED`` is not set).
* ``SCX_EV_REENQ_IMMED``: a task dispatched with ``SCX_ENQ_IMMED`` was
  re-enqueued because the target CPU was not available for immediate execution.
* ``SCX_EV_REENQ_REPEAT``: a reenqueue led to another reenqueue without the
  task running in between; recurring counts indicate that the BPF scheduler
  keeps re-deciding placements it can't honor.
* ``SCX_EV_REFILL_SLICE_DFL``: a task's time slice was refilled with the
  default value (``SCX_SLICE_DFL``).
* ``SCX_EV_BYPASS_DURATION``: total nanoseconds spent in bypass mode.
* ``SCX_EV_BYPASS_DISPATCH``: number of tasks dispatched while in bypass mode.
* ``SCX_EV_BYPASS_ACTIVATE``: number of times bypass mode was activated.
* ``SCX_EV_INSERT_NOT_OWNED``: attempted to insert a task not owned by this
  scheduler into a DSQ; such attempts are silently ignored.
* ``SCX_EV_SUB_BYPASS_DISPATCH``: tasks dispatched from sub-scheduler bypass
  DSQs (only relevant with ``CONFIG_EXT_SUB_SCHED``).

``tools/sched_ext/scx_show_state.py`` is a drgn script which shows more
detailed information:

.. code-block:: none

    # tools/sched_ext/scx_show_state.py
    ops           : simple
    enabled       : 1
    switching_all : 1
    switched_all  : 1
    enable_state  : enabled (2)
    aborting      : False
    bypass_depth  : 0
    nr_rejected   : 0
    enable_seq    : 1

Whether a given task is on sched_ext can be determined as follows:

.. code-block:: none

    # grep ext /proc/self/sched
    ext.enabled                                  :                    1

The Basics
==========

Userspace can implement an arbitrary BPF scheduler by loading a set of BPF
programs that implement ``struct sched_ext_ops``. The only mandatory field
is ``ops.name`` which must be a valid BPF object name. All operations are
optional. The following modified excerpt is from
``tools/sched_ext/scx_simple.bpf.c`` showing a minimal global FIFO scheduler.

.. code-block:: c

    /*
     * Decide which CPU a task should be migrated to before being
     * enqueued (either at wakeup, fork time, or exec time). If an
     * idle core is found by the default ops.select_cpu() implementation,
     * then insert the task directly into SCX_DSQ_LOCAL and skip the
     * ops.enqueue() callback.
     *
     * Note that this implementation has exactly the same behavior as the
     * default ops.select_cpu implementation. The behavior of the scheduler
     * would be exactly same if the implementation just didn't define the
     * simple_select_cpu() struct_ops prog.
     */
    s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p,
                       s32 prev_cpu, u64 wake_flags)
    {
            s32 cpu;
            /* Need to initialize or the BPF verifier will reject the program */
            bool direct = false;

            cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);

            if (direct)
                    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

            return cpu;
    }

    /*
     * Do a direct insertion of a task to the global DSQ. This ops.enqueue()
     * callback will only be invoked if we failed to find a core to insert
     * into in ops.select_cpu() above.
     *
     * Note that this implementation has exactly the same behavior as the
     * default ops.enqueue implementation, which just dispatches the task
     * to SCX_DSQ_GLOBAL. The behavior of the scheduler would be exactly same
     * if the implementation just didn't define the simple_enqueue struct_ops
     * prog.
     */
    void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
    {
            scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
    }

    s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
    {
            /*
             * By default, all SCHED_EXT, SCHED_OTHER, SCHED_IDLE, and
             * SCHED_BATCH tasks should use sched_ext.
             */
            return 0;
    }

    void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
    {
            exit_type = ei->type;
    }

    SEC(".struct_ops")
    struct sched_ext_ops simple_ops = {
            .select_cpu             = (void *)simple_select_cpu,
            .enqueue                = (void *)simple_enqueue,
            .init                   = (void *)simple_init,
            .exit                   = (void *)simple_exit,
            .name                   = "simple",
    };

Dispatch Queues
---------------

To match the impedance between the scheduler core and the BPF scheduler,
sched_ext uses DSQs (dispatch queues) which can operate as both a FIFO and a
priority queue. By default, there is one global FIFO (``SCX_DSQ_GLOBAL``),
and one local DSQ per CPU (``SCX_DSQ_LOCAL``). The BPF scheduler can manage
an arbitrary number of DSQs using ``scx_bpf_create_dsq()`` and
``scx_bpf_destroy_dsq()``.

A CPU always executes a task from its local DSQ. A task is "inserted" into a
DSQ. A task in a non-local DSQ is "move"d into the target CPU's local DSQ.

When a CPU is looking for the next task to run, if the local DSQ is not
empty, the first task is picked. Otherwise, the CPU tries to move a task
from the global DSQ. If that doesn't yield a runnable task either,
``ops.dispatch()`` is invoked.

Scheduling Cycle
----------------

The following briefly shows how a waking task is scheduled and executed.

1. When a task is waking up, ``ops.select_cpu()`` is the first operation
   invoked. This serves two purposes. First, CPU selection optimization
   hint. Second, waking up the selected CPU if idle.

   The CPU selected by ``ops.select_cpu()`` is an optimization hint and not
   binding. The actual decision is made at the last step of scheduling.
   However, there is a small performance gain if the CPU
   ``ops.select_cpu()`` returns matches the CPU the task eventually runs on.

   A side-effect of selecting a CPU is waking it up from idle. While a BPF
   scheduler can wake up any cpu using the ``scx_bpf_kick_cpu()`` helper,
   using ``ops.select_cpu()`` judiciously can be simpler and more efficient.

   Note that the scheduler core will ignore an invalid CPU selection, for
   example, if it's outside the allowed cpumask of the task.

   A task can be immediately inserted into a DSQ from ``ops.select_cpu()``
   by calling ``scx_bpf_dsq_insert()`` or ``scx_bpf_dsq_insert_vtime()``.

   If the task is inserted into ``SCX_DSQ_LOCAL`` from
   ``ops.select_cpu()``, it will be added to the local DSQ of whichever CPU
   is returned from ``ops.select_cpu()``. Additionally, inserting directly
   from ``ops.select_cpu()`` will cause the ``ops.enqueue()`` callback to
   be skipped.

   Any other attempt to store a task in BPF-internal data structures from
   ``ops.select_cpu()`` does not prevent ``ops.enqueue()`` from being
   invoked. This is discouraged, as it can introduce racy behavior or
   inconsistent state.

2. Once the target CPU is selected, ``ops.enqueue()`` is invoked (unless the
   task was inserted directly from ``ops.select_cpu()``). ``ops.enqueue()``
   can make one of the following decisions:

   * Immediately insert the task into either the global or a local DSQ by
     calling ``scx_bpf_dsq_insert()`` with one of the following options:
     ``SCX_DSQ_GLOBAL``, ``SCX_DSQ_LOCAL``, or ``SCX_DSQ_LOCAL_ON | cpu``.

   * Immediately insert the task into a custom DSQ by calling
     ``scx_bpf_dsq_insert()`` with a DSQ ID which is smaller than 2^63.

   * Queue the task on the BPF side.

   **Task State Tracking and ops.dequeue() Semantics**

   A task is in the "BPF scheduler's custody" when the BPF scheduler is
   responsible for managing its lifecycle. A task enters custody when it is
   dispatched to a user DSQ or stored in the BPF scheduler's internal data
   structures. Custody is entered only from ``ops.enqueue()`` for those
   operations. The only exception is dispatching to a user DSQ from
   ``ops.select_cpu()``: although the task is not yet technically in BPF
   scheduler custody at that point, the dispatch has the same semantic
   effect as dispatching from ``ops.enqueue()`` for custody-related
   purposes.

   Once ``ops.enqueue()`` is called, the task may or may not enter custody
   depending on what the scheduler does:

   * **Directly dispatched to terminal DSQs** (``SCX_DSQ_LOCAL``,
     ``SCX_DSQ_LOCAL_ON | cpu``, or ``SCX_DSQ_GLOBAL``): the BPF scheduler
     is done with the task - it either goes straight to a CPU's local run
     queue or to the global DSQ as a fallback. The task never enters (or
     exits) BPF custody, and ``ops.dequeue()`` will not be called.

   * **Dispatch to user-created DSQs** (custom DSQs): the task enters the
     BPF scheduler's custody. When the task later leaves BPF custody
     (dispatched to a terminal DSQ, picked by core-sched, or dequeued for
     sleep/property changes), ``ops.dequeue()`` will be called exactly
     once.

   * **Stored in BPF data structures** (e.g., internal BPF queues): the
     task is in BPF custody. ``ops.dequeue()`` will be called when it
     leaves (e.g., when ``ops.dispatch()`` moves it to a terminal DSQ, or
     on property change / sleep).

   Note that ``ops.enqueue()`` can be called multiple times in a row without
   an intervening call to ``ops.dequeue()``. This can happen, for example,
   when a task on a user-created DSQ is re-enqueued using
   ``scx_bpf_dsq_reenq()``. The task stays in BPF custody the entire time.

   When a task leaves BPF scheduler custody, ``ops.dequeue()`` is invoked.
   The dequeue can happen for different reasons, distinguished by flags:

   1. **Regular dispatch**: when a task in BPF custody is dispatched to a
      terminal DSQ from ``ops.dispatch()`` (leaving BPF custody for
      execution), ``ops.dequeue()`` is triggered without any special flags.

   2. **Core scheduling pick**: when ``CONFIG_SCHED_CORE`` is enabled and
      core scheduling picks a task for execution while it's still in BPF
      custody, ``ops.dequeue()`` is called with the
      ``SCX_DEQ_CORE_SCHED_EXEC`` flag.

   3. **Scheduling property change**: when a task property changes (via
      operations like ``sched_setaffinity()``, ``sched_setscheduler()``,
      priority changes, CPU migrations, etc.) while the task is still in
      BPF custody, ``ops.dequeue()`` is called with the
      ``SCX_DEQ_SCHED_CHANGE`` flag set in ``deq_flags``.

   **Important**: Once a task has left BPF custody (e.g., after being
   dispatched to a terminal DSQ), property changes will not trigger
   ``ops.dequeue()``, since the task is no longer managed by the BPF
   scheduler.

3. When a CPU is ready to schedule, it first looks at its local DSQ. If
   empty, it then looks at the global DSQ. If there still isn't a task to
   run, ``ops.dispatch()`` is invoked which can use the following two
   functions to populate the local DSQ.

   * ``scx_bpf_dsq_insert()`` inserts a task to a DSQ. Any target DSQ can be
     used - ``SCX_DSQ_LOCAL``, ``SCX_DSQ_LOCAL_ON | cpu``,
     ``SCX_DSQ_GLOBAL`` or a custom DSQ. While ``scx_bpf_dsq_insert()``
     currently can't be called with BPF locks held, this is being worked on
     and will be supported. ``scx_bpf_dsq_insert()`` schedules insertion
     rather than performing them immediately. There can be up to
     ``ops.dispatch_max_batch`` pending tasks.

   * ``scx_bpf_dsq_move_to_local()`` moves a task from the specified non-local
     DSQ to the dispatching DSQ. This function cannot be called with any BPF
     locks held. ``scx_bpf_dsq_move_to_local()`` flushes the pending insertions
     tasks before trying to move from the specified DSQ.

4. After ``ops.dispatch()`` returns, if there are tasks in the local DSQ,
   the CPU runs the first one. If empty, the following steps are taken:

   * Try to move from the global DSQ. If successful, run the task.

   * If ``ops.dispatch()`` has dispatched any tasks, retry #3.

   * If the previous task is an SCX task and still runnable, keep executing
     it (see ``SCX_OPS_ENQ_LAST``).

   * Go idle.

Note that the BPF scheduler can always choose to dispatch tasks immediately
in ``ops.enqueue()`` as illustrated in the above simple example. If only the
built-in DSQs are used, there is no need to implement ``ops.dispatch()`` as
a task is never queued on the BPF scheduler and both the local and global
DSQs are executed automatically.

``scx_bpf_dsq_insert()`` inserts the task on the FIFO of the target DSQ. Use
``scx_bpf_dsq_insert_vtime()`` for the priority queue. Internal DSQs such as
``SCX_DSQ_LOCAL`` and ``SCX_DSQ_GLOBAL`` do not support priority-queue
dispatching, and must be dispatched to with ``scx_bpf_dsq_insert()``. See
the function documentation and usage in ``tools/sched_ext/scx_simple.bpf.c``
for more information.

Task Lifecycle
--------------

The following pseudo-code presents a rough overview of the entire lifecycle
of a task managed by a sched_ext scheduler:

.. code-block:: c

    ops.init_task();            /* A new task is created */
    ops.enable();               /* Enable BPF scheduling for the task */

    while (task in SCHED_EXT) {
        if (task can migrate)
            ops.select_cpu();   /* Called on wakeup (optimization) */

        ops.runnable();         /* Task becomes ready to run */

        while (task_is_runnable(task)) {
            if (task is not in a DSQ || task->scx.slice == 0) {
                ops.enqueue();  /* Task can be added to a DSQ */

                /* Task property change (i.e., affinity, nice, etc.)? */
                if (sched_change(task)) {
                    ops.dequeue(); /* Exiting BPF scheduler custody */
                    ops.quiescent();

                    /* Property change callback, e.g. ops.set_weight() */

                    ops.runnable();
                    continue;
                }

                /* Any usable CPU becomes available */

                ops.dispatch();     /* Task is moved to a local DSQ */
                ops.dequeue();      /* Exiting BPF scheduler custody */
            }

            ops.running();      /* Task starts running on its assigned CPU */

            while (task_is_runnable(task) && task->scx.slice > 0) {
                ops.tick();     /* Called every 1/HZ seconds */

                if (task->scx.slice == 0)
                    ops.dispatch(); /* task->scx.slice can be refilled */
            }

            ops.stopping();     /* Task stops running (time slice expires or wait) */
        }

        ops.quiescent();        /* Task releases its assigned CPU (wait) */
    }

    ops.disable();              /* Disable BPF scheduling for the task */
    ops.exit_task();            /* Task is destroyed */

Note that the above pseudo-code does not cover all possible state transitions
and edge cases, to name a few examples:

* ``ops.dispatch()`` may fail to move the task to a local DSQ due to a racing
  property change on that task, in which case ``ops.dispatch()`` will be
  retried.

* The task may be direct-dispatched to a local DSQ from ``ops.enqueue()``,
  in which case ``ops.dispatch()`` and ``ops.dequeue()`` are skipped and we go
  straight to ``ops.running()``.

* Property changes may occur at virtually any point during the task's lifecycle,
  not just when the task is queued and waiting to be dispatched. For example,
  changing a property of a running task will lead to the callback sequence
  ``ops.stopping()`` -> ``ops.quiescent()`` -> (property change callback) ->
  ``ops.runnable()`` -> ``ops.running()``.

* A sched_ext task can be preempted by a task from a higher-priority scheduling
  class, in which case it will exit the tick-dispatch loop even though it is runnable
  and has a non-zero slice.

See the "Scheduling Cycle" section for a more detailed description of how
a freshly woken up task gets on a CPU.

Where to Look
=============

* ``include/linux/sched/ext.h`` defines the core data structures and
  constants, while the ops table (``struct sched_ext_ops``) is defined in
  ``kernel/sched/ext/internal.h``.

* ``kernel/sched/ext/ext.c`` contains sched_ext core implementation and helpers.
  The functions prefixed with ``scx_bpf_`` can be called from the BPF
  scheduler.

* ``kernel/sched/ext/idle.c`` contains the built-in idle CPU selection policy.

* ``tools/sched_ext/`` hosts example BPF scheduler implementations.

  * ``scx_simple[.bpf].c``: Minimal global FIFO scheduler example using a
    custom DSQ.

  * ``scx_qmap[.bpf].c``: A multi-level FIFO scheduler supporting five
    levels of priority implemented with arena-backed doubly-linked lists.

  * ``scx_central[.bpf].c``: A central FIFO scheduler where all scheduling
    decisions are made on one CPU, demonstrating ``LOCAL_ON`` dispatching,
    tickless operation, and kthread preemption.

  * ``scx_cpu0[.bpf].c``: A scheduler that queues all tasks to a shared DSQ
    and only dispatches them on CPU0 in FIFO order. Useful for testing bypass
    behavior.

  * ``scx_flatcg[.bpf].c``: A flattened cgroup hierarchy scheduler
    implementing hierarchical weight-based cgroup CPU control by compounding
    each cgroup's share at every level into a single flat scheduling layer.

  * ``scx_pair[.bpf].c``: A core-scheduling example that always makes
    sibling CPU pairs execute tasks from the same CPU cgroup.

  * ``scx_sdt[.bpf].c``: A variation of ``scx_simple`` demonstrating BPF
    arena memory management for per-task data.

  * ``scx_userland[.bpf].c``: A minimal scheduler demonstrating user space
    scheduling. Tasks with CPU affinity are direct-dispatched in FIFO order;
    all others are scheduled in user space by a simple vruntime scheduler.

Extending fair scheduling
=========================

``sched_ext_ops`` allows a BPF struct_ops program to extend selected operations
of the fair scheduling class without replacing it. It requires
``CONFIG_SCHED_CLASS_EXT`` and the ``SCX_OPS_FAIR`` flag. The interface
supports overriding initial CPU placement and load balancing for fair-class
tasks.

The interface has two optional operations::

    struct sched_ext_ops {
            s32 (*fair_select_cpu)(struct task_struct *p, s32 prev_cpu,
                                   u64 wake_flags);
            s32 (*fair_balance)(const struct fair_ext_balance_ctx *ctx);
            u64 flags; /* SCX_OPS_FAIR */
            u32 timeout_ms;
            char name[SCX_OPS_NAME_LEN];
    };

``fair_select_cpu()`` runs for fair-class wakeup, fork, and exec placement
while the task's ``pi_lock`` is held. A non-negative return value requests that
CPU. A negative return value asks the kernel to use ``select_task_rq_fair()``.
CPU numbers which are out of range, offline, or outside the task's effective
affinity mask also fall back to ``select_task_rq_fair()``.

Only one fair-extension ``sched_ext_ops`` instance may be attached at a time.
It cannot be combined with regular sched_ext callbacks or sub-schedulers.
Conversely, regular sched_ext policies cannot implement ``fair_*`` callbacks.
Detaching the BPF link immediately restores the fair scheduler's default
policy.

Runtime state
-------------

The current fair_ext state is available from sysfs::

    # cat /sys/kernel/fair_ext/state
    enabled

The possible states are ``disabled`` when no policy is attached, ``enabled``
when an attached policy is active, and ``faulted`` when the watchdog has
disabled the callbacks but the BPF link remains attached. The latter state
allows a policy manager to distinguish a failed policy from an ordinary
detach.

The struct_ops map ID of the attached policy is available in
``/sys/kernel/fair_ext/map_id``. It contains zero when no policy is attached
and can otherwise be correlated with ``bpftool link show`` and
``bpftool struct_ops show``.

Fair placement within a CPU subset
----------------------------------

``fair_select_cpu()`` can delegate the placement decision back to the fair
scheduler while restricting the CPUs it may consider::

    s32 scx_fair_bpf_select_cpu(struct task_struct *p, s32 prev_cpu,
                                u64 wake_flags,
                                const struct cpumask *preferred_mask__nullable);

The kfunc intersects ``preferred_mask`` with the task's effective affinity mask
and runs normal native fair selection on the result. Passing ``NULL`` skips the
intersection and runs fair selection directly on the task's effective affinity
mask. A callback can query the selected CPU with::

    s32 scx_fair_bpf_cpu_idle(s32 cpu);

This callback-scoped kfunc returns one if the CPU is currently available idle,
zero if it is busy, or a negative error for an invalid or inactive CPU. A soft
preference can therefore use two selections::

    cpu = scx_fair_bpf_select_cpu(p, prev_cpu, wake_flags, preferred_mask);
    if (cpu >= 0 && scx_fair_bpf_cpu_idle(cpu) == 0)
            cpu = scx_fair_bpf_select_cpu(p, prev_cpu, wake_flags, NULL);

The task must be the task passed to the active ``fair_select_cpu()`` callback.
The kfunc returns ``-EINVAL`` if the mask intersection is empty or ``prev_cpu``
is invalid. Both kfuncs are only available from
``sched_ext_ops.fair_select_cpu()`` and the mask must remain valid for the
duration of the call. Idle state may change immediately after it is queried,
so the preference is best effort.

The preferred mask restricts this initial placement decision only. Without a
``fair_balance()`` policy, fair load balancing may subsequently migrate the
task to any CPU allowed by its normal affinity and cpuset constraints.

Load balancing
--------------

``fair_balance()`` runs from fair's periodic, NOHZ-idle, and newly-idle load
balancing paths. It receives only policy-relevant local state::

    struct fair_ext_balance_ctx {
            s32 cpu;
            u32 nr_running;
            u64 flags;
    };

``cpu`` identifies the CPU on whose behalf balancing is running and
``nr_running`` is its number of runnable fair tasks.
``FAIR_EXT_BALANCE_IDLE`` indicates an idle balance pass,
and ``FAIR_EXT_BALANCE_NEWLY_IDLE`` additionally identifies the newly-idle
path. ``cpu`` is always the destination runqueue being balanced and may
differ from the CPU executing the callback. Internal scheduling domains,
groups, runqueues, and load-balancer state are not exposed.

A policy can inspect whether a preferred CPU subset has spare capacity with::

    s32 scx_fair_bpf_has_idle_cpu(const struct cpumask *preferred_mask);

The kfunc returns one if an active CPU in the mask is currently available
idle, zero if none is, or a negative error for an invalid call. It is scoped to
``fair_balance()`` and provides only an instantaneous capacity hint; runqueue
and load-balancer internals remain hidden.

Returning ``FAIR_EXT_BALANCE_HANDLED`` from ``fair_balance()`` suppresses
native fair load balancing for that pass. ``FAIR_EXT_BALANCE_CONTINUE`` allows
native balancing to continue after the callback, so the callback can augment
fair balancing. Negative errors and unrecognized return values also fail open
to native balancing. The callback can therefore augment fair balancing or
replace an individual pass without manipulating runqueues directly.

Runnable-task watchdog
----------------------

A fair_ext policy can repeatedly suppress native balancing or continually
favor other tasks through vlag selection.
The runnable-task watchdog is a best-effort safety mechanism. It restores
native fair behavior when a task is observed eligible without making runtime
progress for longer than ``sched_ext_ops.timeout_ms``. A zero timeout selects
the default of 30 seconds, and values greater than 30 seconds are rejected.

The watchdog requires the task to be observed in consecutive scans. A task
which migrates from a runqueue not yet scanned to one already scanned can be
missed for that pass, restarting its observation window and delaying detection
beyond the configured timeout. This conservative behavior avoids disabling an
extension based on an uncertain runnable interval without adding bookkeeping
to fair's enqueue and dequeue paths.

The wait timestamp is reset when a task runs or is not observed in the
preceding scan. Delayed-dequeue, throttled, and SCHED_IDLE tasks are excluded.
A runqueue is not checked while a higher scheduling class owns its CPU. The
watchdog itself runs in a low-priority FIFO kernel thread so a broken fair
policy cannot prevent recovery.

On timeout, the kernel logs the stalled task, CPU, and wait duration, disables
all callbacks, and patches the fair_ext hooks back out. The BPF link remains
attached but inactive so its owner can inspect counters and detach it; another
fair_ext policy cannot attach until that link is detached.

Scope
-----

Fair continues to control runqueue ordering, preemption, bandwidth accounting,
and migration mechanics. A positive ``fair_balance()`` result replaces
periodic, NOHZ, or newly-idle fair balancing for that pass, but NUMA, affinity,
CPU-hotplug, and other scheduler mechanisms may still move a task after
``fair_select_cpu()`` returns. A policy which requires strict placement must
repair or otherwise account for those migrations.

Example policy
--------------

``tools/sched_ext/scx_fair_tiered`` treats a command-line CPU list as a soft
preference. It uses native fair selection within that list and falls back to
unrestricted fair placement when the selected preferred CPU is busy. Its
balance callback prevents non-preferred CPUs from pulling work while preferred
idle capacity exists. Once the preferred tier is full, native fair balancing
is allowed across all CPUs permitted by task affinity and cpuset constraints.

``tools/sched_ext/scx_fair_vlag`` demonstrates virtual-lag selection
independently. It selects zero virtual lag when fair places a task while leaving
CPU placement, load balancing, request renewal, runtime accounting, and
deadline sizing under native fair control.

Module Parameters
=================

sched_ext exposes two module parameters under the ``sched_ext.`` prefix that
control bypass-mode behaviour. These knobs are primarily for debugging; there
is usually no reason to change them during normal operation. They can be read
and written at runtime (mode 0600) via
``/sys/module/sched_ext/parameters/``.

``sched_ext.slice_bypass_us`` (default: 5000 µs)
    The time slice assigned to all tasks when the scheduler is in bypass mode,
    i.e. during BPF scheduler load, unload, and error recovery. Valid range is
    100 µs to 100 ms.

``sched_ext.bypass_lb_intv_us`` (default: 500000 µs)
    The interval at which the bypass-mode load balancer redistributes tasks
    across CPUs. Set to 0 to disable load balancing during bypass mode. Valid
    range is 0 to 10 s.

ABI Instability
===============

The APIs provided by sched_ext to BPF schedulers programs have no stability
guarantees. This includes the ops table callbacks defined in
``kernel/sched/ext/internal.h`` and the constants defined in
``include/linux/sched/ext.h``, as well as the ``scx_bpf_`` kfuncs defined in
``kernel/sched/ext/ext.c`` and ``kernel/sched/ext/idle.c``.

While we will attempt to provide a relatively stable API surface when
possible, they are subject to change without warning between kernel
versions.
