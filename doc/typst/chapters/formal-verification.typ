#import "../template.typ": *

= Formal Verification <sec:formal-verification>

This chapter is for auditors and developers. The concurrent parts of the
#ac("ESDM") – the seeding and output of its #ac("DRNG", pl: true), the
servers, the frontends, the supervisor and the kernel modules – are modeled in
TLA+ and model checked. Whereas the tests of chapter @sec:testing run some of
the interleavings of threads, the model checker runs all of them within
bounds and returns a trace for every property that does not hold. The chapter
explains what the models cover (section @sec:fv-scope), the language and the
tools (section @sec:fv-tla), how the code is turned into a model (section
@sec:fv-approach) and under which assumptions (section @sec:fv-assumptions),
presents a model in TLA+ step by step (section @sec:fv-example), gives an
overview of the models (section @sec:fv-overview), describes each model
with its properties and results (section @sec:fv-models), shows how the
models are validated against the code (section @sec:fv-validation), and
states their limitations (section @sec:fv-limitations). Section
@sec:fv-findings summarizes the findings.

== Scope <sec:fv-scope>

Each subsystem of the #ac("ESDM") calls for its own methods: model checking
for the logic of threads, locks and state machines; fuzzing, sanitizers and
bounded model checking of the C code for the parsers and memory safety;
known-answer tests and algorithm validation for the cryptographic primitives;
the #ac("SP") 800-90B assessment and health tests for the entropy sources;
virtual machines for the integration with the kernel and the system. Table
@tab:fv-scope lists the subsystems, the methods that fit them and what is
applied today. Model checking covers the #ac("DRNG") manager, the self test
gate, the auxiliary pool, the status in shared memory, the #ac("CUSE")
frontends, the #ac("EGD") server, the supervisor, the #ac("RPC") server and
client and the kernel modules `esdm_es` and `esdm_cdev`; the testing of
chapter @sec:testing covers every subsystem.

#figure(
  table(columns: (1fr, 1.1fr, 1.3fr), align: left + horizon,
    table.header([Subsystem], [Methods that fit], [Applied today]),
    [#ac("DRNG") manager: seeding, reseeding, output
      (`esdm/esdm_drng_mgr.c`)],
    [Model checking of locks, flags and entropy accounting; deductive
      proof of the accounting],
    [TLA+ model (section @sec:fv-reseed); test suite; security tests of
      reseeding and of output stopping with a failed Jitter #acs("RNG")\;
      thread sanitizer],
    [#ac("ES") manager: seeding decision, NTG.1, monitor
      (`esdm/esdm_es_mgr.c`)],
    [Model checking of the seeding decision and the triggers],
    [Seeding decision with NTG.1 in the TLA+ model, the monitor as a trigger
      only; test suite],
    [Entropy sources: Jitter #acs("RNG"), #ac("CPU"), interrupts and
      scheduler, #ac("eBPF"), #ac("HWRAND"), #ac("TPM"), kernel #acs("RNG"),
      external],
    [#ac("SP") 800-90B assessment of raw data; health tests; model checking
      of the collector locking; fuzzing of the external source protocol],
    [Assessments of chapters @sec:kernel-es-assessment and
      @sec:ebpf-assessment; test suite per source; `ebpf_raw` machine; in the
      TLA+ model a source delivers any amount],
    [Auxiliary pool (`esdm/esdm_es_aux.c`)],
    [Model checking of insertion and extraction against the atomic entropy
      count; bounded model checking of the count arithmetic],
    [TLA+ model (section @sec:fv-aux); test suite, including a failing
      #ac("XOF")\; library #ac("API") fuzzing],
    [Cryptographic primitives and backends],
    [Known-answer tests; #ac("ACVP") validation; constant-time analysis;
      verified implementations],
    [Known-answer tests in the suite; self tests at start-up and every 600
      seconds (section @sec:self-tests)],
    [Self tests and operational state (`esdm/esdm_selftest.c`)],
    [Model checking of the gate on output],
    [TLA+ model (section @sec:fv-selftest); security tests: a failed self
      test stops all output, the periodic self test worker and the reseed
      worker],
    [#ac("RPC") server and client (`service-rpc/`)],
    [Model checking of the workers, the start-up and shutdown and the response
      matching; fuzzing of the codec],
    [TLA+ models of the server and the client (sections @sec:fv-rpc-server
      and @sec:fv-rpc-client); fuzzing of requests, responses and the client;
      robustness tests of server and client],
    [#ac("EGD") server and client (`service-egd/`)],
    [Model checking of the single worker and its deferred clients; fuzzing],
    [TLA+ model of the server (section @sec:fv-egd); fuzzing; test suite;
      `egd_gnupg` and `egd_openssh` machines],
    [#ac("CUSE") and `getrandom` frontends (`frontends/`)],
    [Model checking of the blocking and poll semantics],
    [TLA+ model (section @sec:fv-cuse); test suite (as root); `live`
      machines],
    [Status in shared memory (`esdm/esdm_shm_status.c`)],
    [Model checking of the writer and reader protocol],
    [TLA+ model (section @sec:fv-shm-status); test suite],
    [Server process: privilege drop, #ac("PID") namespace supervisor
      (`frontends/server/`, `common/linux_support.c`)],
    [Model checking of the supervisor and child life cycle and its signals],
    [TLA+ model of the supervisor (section @sec:fv-supervisor); test suite;
      virtual machine tests; hardening of chapter @sec:hardening],
    [Kernel modules `esdm_es` and `esdm_cdev` (`kernel/`)],
    [Static analysis; model checking of the buffer, the health test gate,
      the wakeups and the connections],
    [TLA+ models of the `esdm_es` buffer and of the `esdm_cdev` devices and
      connections (sections @sec:fv-kernel-es, @sec:fv-kernel-cdev and
      @sec:fv-kernel-cdev-conn); builds with `W=1` and warnings as errors
      against every supported kernel; `live` and `cdev` machines],
    [All C code],
    [Sanitizers; fuzzing; static analysis; bounded model checking],
    [Address and undefined behavior sanitizers in #ac("CI")\; CodeQL; fuzz
      replay in the suite; `memory-debug`],
  ),
  caption: [Subsystems of the #ac("ESDM"), methods that fit them and what is
    applied today],
) <tab:fv-scope>

== TLA+ and the Tools <sec:fv-tla>

TLA+ is a language for specifying concurrent and distributed systems, based
on the Temporal Logic of Actions @tla @specifying-systems. A specification
describes a system as a state machine: its variables, a predicate for the
initial states and a next-state relation made of actions, each a predicate
over the values of the variables before and after one step. The behaviors of
a system are the sequences of states the specification allows, and its
properties are formulas of temporal logic over them: an invariant holds in
every state of every behavior, whereas a liveness property such as "every
request is eventually answered" holds over a behavior as a whole.

PlusCal @pluscal is an algorithm language with a C-like syntax that its
translator turns into a TLA+ specification. A PlusCal process stands for a
thread, a procedure for a function, and a label marks the end of an atomic
step; the translation makes the program counter of each process explicit.
The models of the #ac("ESDM") are written in PlusCal, which keeps them close
to the C code, except for the supervisor model, which is written in plain
TLA+ because signal handlers interrupt the code like asynchronous events.

TLC @tlc is an explicit-state model checker for TLA+. A configuration gives
values to the constants of a specification, which makes its state space
finite, and names the properties to check. TLC enumerates every reachable
state breadth first, checks the invariants in each of them and the temporal
properties, under the fairness the specification states, on the graph of the
states. For a violated property, TLC reports a behavior leading to the
violation – for an invariant, a shortest one. The properties of a
configuration checked without a violation hold for every interleaving of its
processes within its bounds.

#paragraph[Why TLA+][The choice of the method weighs three things against
each other: the effort to apply it, the defects it finds, and how many
people can read and maintain the result. TLA+ with a model checker was
chosen because this ratio is the best one for the concurrent parts of the
#ac("ESDM"); table @tab:fv-methods compares it with the alternatives. The
defects of these parts are interleavings: a check and an action that
another thread separates, a wakeup that arrives before its waiter, a lock
taken in the wrong order. A model checker enumerates the interleavings of a
small instance and returns a short one that violates a property, as a
sequence of steps named after the C functions. A developer who knows the
code can follow such a trace without knowing a logic or a proof language,
and learns PlusCal in a fraction of the time a proof language takes. The
method
is established in industry for exactly this class of defects
@aws-formal-methods.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (1.15fr, 1.4fr, 1.6fr), align: left + top,
    table.header([Method], [What it would give], [Why it is not the
      method of this chapter]),
    [Interactive theorem provers: Rocq, Isabelle/HOL, Lean], [A
      machine-checked proof for every number of threads and every value of
      the counters, and, with a formal semantics of C, a proof about the
      code itself instead of a model of it], [The effort is larger by
      orders of magnitude: the proof, not the model, is the bulk of the
      work, and it has to be repaired with every change of the code. Few
      developers can read or maintain it, and a failed proof attempt does
      not name the interleaving that goes wrong. The benefit would be the
      removal of the bounds and of the gap between model and code (section
      @sec:fv-limitations); for code that changes with every release, this
      does not justify the cost],
    [Proofs of the same specifications with the TLA+ proof system], [The
      properties for unbounded instances, on the models as they are], [Not
      done; it is the path to remove the bounds of single models without
      changing the method, should a model warrant it],
    [Other explicit-state model checkers, e.g. SPIN], [The same kind of
      result], [No decisive difference. PlusCal reads like the C code it
      models, TLA+ expresses the data of the models – sets, records,
      sequences – directly, and fairness and temporal properties are part of
      the language],
    [Bounded model checking and static analysis of the C code], [Defects of
      the code itself, without a hand-written model], [Suited to memory
      safety and to sequential code, where they are applied (chapter
      @sec:testing); the interleavings of several threads over locks,
      condition variables and sockets exceed what they explore],
    [Tests, stress tests, thread sanitizer], [Defects in the executed
      code], [Applied as well (chapter @sec:testing), but they show the
      interleavings that happen to occur, not all of them: the test suite
      passed on the code in which the models found the defects of table
      @tab:fv-findings],
  )
}
, caption: [Verification methods considered for the concurrent parts of the
  #ac("ESDM")]) <tab:fv-methods>

#par(first-line-indent: 0pt)[The price of this choice is stated in section
@sec:fv-limitations: the models are finite instances, written by hand, and
nothing proves that they describe the code. Within these limits, the
models found the defects of table @tab:fv-findings in code that the test
suite had passed.]

The models are checked with the TLA+ tools @tlatools in version 1.8.0 – the
parser SANY, the PlusCal translator `pcal` and TLC – as nixpkgs packages them
(`tlaplus18`), on the OpenJDK runtime that comes with them. Each model is a
file `tests/tla/<model>.tla` with its configurations in the directory
`tests/tla/<model>/`. `tests/tla/check.sh` translates the models and checks
the configurations given as arguments or, if none is given, all
configurations; those marked with a line `\* Slow` are left out unless
`TLA_ALL=1` is set. The script accepts a configuration when TLC finds no
error, or when it finds exactly the violation the line `\* Expect:` of the
configuration names. The check `tla` of the Nix flake runs it on every
configuration not marked slow:

```sh
nix shell nixpkgs#tlaplus18 -c tests/tla/check.sh
nix shell nixpkgs#tlaplus18 -c tests/tla/check.sh EsdmReseed/Drg4.cfg
TLA_ALL=1 nix shell nixpkgs#tlaplus18 -c tests/tla/check.sh
nix build .#checks.x86_64-linux.tla
```

`check.sh` limits the Java heap of TLC to 1 GiB (`JAVA_TOOL_OPTIONS`), so
that several runs fit side by side; TLC stores on disk what does not fit
into the heap.

== Modeling Approach <sec:fv-approach>

#paragraph[Processes and steps][Every thread of the code that takes part is a
process of a model: requesters, worker threads, monitors, signal handlers.
The C functions they run are procedures, and each label ends an atomic step
and is named after the C function it stems from. One step is one access to an
atomic variable, one critical section under a lock, or one system call; code
between two such points that touches only data of its own thread belongs to
the step before it. Where the code holds no lock across two accesses, the
model takes two steps, so that every interleaving the code allows is
checked.]

#paragraph[Environment][Whatever the code does not control is modeled as a
separate process or as a nondeterministic choice: an entropy source credits
any amount up to what is asked for, including none; a seed operation or a
system call fails; clients connect, send, read and close at any time; signals
arrive; time passes and lets a reseed fall due. A model checks the code
against every such behavior, not against the typical ones.]

#paragraph[Properties][Safety properties are invariants – of the state, of
a ghost variable that records what the code does not keep, such as the
entropy a #ac("DRNG") received since its last output or the signals sent to
a #ac("PID"), or of a set of violations a step notes when it does what it
must not. Progress is stated as temporal properties, such as a request
returning or a waiting thread waking. They hold under fairness and, where
the environment decides, under an assumption written into the property, for
example that the entropy sources eventually deliver permanently
($diamond.stroked square.stroked "good" => dots$).]

#paragraph[Defects and fixes][A defect is kept as a configuration that
demonstrates it on the code before the fix: its line `\* Expect:` names the
property, and `check.sh` accepts the configuration only when TLC finds that
violation. `Expect: Deadlock` asks for a state without a step. A temporal
property is accepted as expected only when it is the single temporal property
of its configuration, as TLC does not name the one that failed; where
another violation of the same property could be found by accident, a line
`\* Witness:` holds a pattern that a state of the counterexample has to
match. A switch of the model turns the fix on. Once the fix is in the
code, every other configuration checks the code with it; a defect not fixed
yet is kept the same way, with the fix the model suggests. Where no
earlier revision violated a property, a seeded defect – a switch that
removes one guard of the code as it is – shows that it can fail; section
@sec:fv-validation states how far this was done.]

#paragraph[Deadlock and termination][TLC reports every state without a step
as a deadlock. The check is on in all configurations but those few that
expect a temporal property to fail on a hang, where TLC would report the
deadlock first, and those the sections of the models name with their
reason. For the check to mean
something, a model ends or idles explicitly: a process that is done takes a
terminating step, a server that waits for work stutters in exactly the
states in which waiting is correct, and the environment is bounded, so that
no process that can always step hides a thread that cannot. A hang within a
cycle of the others is found by an invariant on the waiting state or by a
liveness property.]

#paragraph[Configurations][A configuration bounds the instance: two or three
threads of a kind, two #ac("DRNG") instances besides the prediction
resistance one, a few requests or clients, counters in coarse units. Within
its bounds TLC checks every interleaving; defects of concurrent code tend to
manifest in small instances already. Configurations that take more than a few
minutes are marked slow; every configuration listed ran to its end.]

== Assumptions <sec:fv-assumptions>

The models take the following as given; the results hold under these
assumptions:

+ Interleaving and atomicity: threads interleave arbitrarily at the step
  boundaries, and each step is atomic. Accesses to C11 atomic variables are
  sequentially consistent, as the default operations used by the code are;
  weaker memory orders are not modeled. The kernel modules get the order the
  models assume from locks, fully ordered atomic operations and barriers that
  pair with acquire reads, as the fix of the health test gate of `esdm_es`
  does (section @sec:fv-kernel-es); this pairing is argued, not checked by
  TLC; for the health test gate a litmus test checks it against the memory
  model of the kernel.
+ Locks: a mutex grants mutual exclusion, a thread blocked on it waits until
  it is released, and a trylock fails exactly while the lock is held. Data the
  code protects by a lock is accessed under it only, except where a model has
  an explicit unlocked access.
+ Fairness: a thread that can proceed continuously (weak fairness) or again
  and again (strong fairness) eventually does; neither the scheduler nor the
  lock implementation nor the kernel starves a thread forever. Only the
  liveness properties depend on it.
+ Environment: inputs are nondeterministic within the ranges a model states;
  the liveness properties assume in addition that the environment eventually
  and permanently behaves well: the entropy sources deliver, clients read their
  responses, descriptors are available.
+ Cryptography: the primitives are ideal. A #ac("DRNG") holds the entropy of
  the seeds injected since its last output, added up, and its output reveals
  nothing about a seed beyond that; conditioning loses none of the entropy
  credited. Only this accounting is modeled, not the primitives.
+ Entropy sources: the entropy a source credits is present in its data, as
  the #ac("SP") 800-90B assessment of chapters @sec:kernel-es-assessment and
  @sec:ebpf-assessment establishes for the kernel sources, and the sources are
  independent, which the NTG.1 rule of two sources requires. Seed length and
  seed entropy differ: a source writes the data of the amount asked for, at
  least the security strength of 256 bits, and credits the entropy it
  estimates in it, such as 240 bits of an NTG.1 Jitter #acs("RNG"). The
  models count the entropy; the length of the seed material follows from the
  code.
+ Operating system and libraries: the kernel and the libraries behave as
  documented – signal delivery and masks, the protection of a #ac("PID")
  namespace init, epoll in level-triggered mode, System V and #ac("POSIX")
  semaphores, the poll handles of #ac("FUSE"), and for the kernel modules the
  interrupt and preemption contexts, spinlocks taken with interrupts
  disabled, #ac("RCU") grace periods, wait queues and delayed work. This
  semantics is taken from the documentation, not checked against the kernel
  sources.
+ Time: the models have no notion of time. A timeout, an interval or a
  backoff is an event that may happen at any step, which covers every timing,
  including timings the real timers exclude.
+ Correspondence: each model follows the C code of the revision it was
  written against, and is kept in step with the code by hand.

== The Models by Example <sec:fv-example>

// Listings start at the left margin, their captions stay centered
#show figure.where(kind: raw): set align(left)

This section presents the reseeding model, `tests/tla/EsdmReseed.tla`, step
by step:
how C code becomes PlusCal and TLA+, how the environment and the properties
are written, and how TLC reports a defect. Table @tab:fv-concepts relates the
constructs of the models to the code.

#figure(
  table(columns: (auto, 1fr, 1.2fr), align: left + horizon,
    table.header([Construct], [Meaning], [In the code]),
    [`process (r \in Req)`], [A set of processes, one per element], [The
      threads of one kind, here the requesters],
    [`procedure seedEs(...)`], [A procedure with parameters and local
      variables, kept on a stack], [A C function and its stack frame, here
      `esdm_drng_seed_es`],
    [`se1:`], [A label: the statements up to the next label are one atomic
      step], [One atomic access, one critical section or one system call],
    [`await P`], [The step is enabled only while `P` holds], [Waiting for a
      lock or a condition],
    [`with (x \in S)`], [A nondeterministic choice: TLC explores every
      element], [Input the code does not control: entropy, failures, arrivals],
    [`either ... or ...`], [Alternative steps, all explored], [Alternative
      behaviors of a thread or the environment],
    [`fair process`, `fair+ process`], [Weak or strong fairness of the
      process], [A scheduler that does not starve a thread that can proceed],
    [Variable], [A component of the global state], [Shared memory: flags,
      counters, the holders of locks],
    [Ghost variable], [State only the properties read: `freshOut`, `viol`],
      [Absent; bookkeeping of the verification],
    [Invariant], [A state predicate checked in every reachable state], [An
      assertion that never fails],
    [Temporal formula], [A property of whole behaviors, with $square.stroked$
      (always) and $diamond.stroked$ (eventually)], [Something that happens
      eventually, such as a request returning],
    [`CONSTANTS` of a configuration], [The values that make an instance
      finite], [Build options and the bounds of the check],
  ),
  caption: [Constructs of the models and what they stand for in the code],
) <tab:fv-concepts>

#paragraph[From C to TLA+][`esdm_unset_fully_seeded` takes a #ac("DRNG") out
of the fully seeded state with two atomic stores that no lock covers
(listing @lst:fv-unset-c). The model takes two steps for them, `us1` and
`us2` (listing @lst:fv-unset-pcal), so that every thread may run between
them: the window in which the flag of all fully seeded #ac("DRNG", pl: true)
is still set, which the invariant `AllSeededSound` admits. The ghost variable
`goodSeed` follows `fully_seeded`. The PlusCal translator turns each step into
a TLA+ action (listing @lst:fv-unset-tla): a predicate over the state before
the step and, primed, after it, which leaves every other variable unchanged.]

#figure(
```c
void esdm_unset_fully_seeded(struct esdm_drng *drng)
{
    atomic_store(&drng->fully_seeded, false);
    esdm_pool_all_nodes_seeded(false);
    if (drng == esdm_drng_init_instance() &&
        atomic_exchange(&esdm_state.esdm_operational, false)) {
        /* ... log, clear the fully seeded state, the status ... */
    }
    esdm_es_mgr_monitor_wakeup();
}
```,
  caption: [`esdm_unset_fully_seeded` in `esdm/esdm_es_mgr.c`, abridged],
) <lst:fv-unset-c>

#figure(
```tla
procedure unset(ud)
{
us1: fs[ud] := FALSE;
     goodSeed[ud] := FALSE;
us2: allSeeded := FALSE;
     if (ud = 0) operational := FALSE;
     return;
}
```,
  caption: [The procedure `unset` of the model in PlusCal],
) <lst:fv-unset-pcal>

#figure(
```tla
us1(self) == /\ pc[self] = "us1"
             /\ fs' = [fs EXCEPT ![ud[self]] = FALSE]
             /\ goodSeed' = [goodSeed EXCEPT ![ud[self]] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "us2"]
             /\ UNCHANGED << force, initiated, used, ... >>

us2(self) == /\ pc[self] = "us2"
             /\ allSeeded' = FALSE
             /\ IF ud[self] = 0
                   THEN /\ operational' = FALSE
                   ELSE /\ TRUE
                        /\ UNCHANGED operational
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ud' = [ud EXCEPT ![self] = Head(stack[self]).ud]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, ... >>
```,
  caption: [The TLA+ actions the translator generates for `unset`, abridged],
) <lst:fv-unset-tla>

#paragraph[A step with its environment][The emergency reseeding of
`esdm_drng_seed_es` collects, decides whether the collected entropy suffices
and injects, until a #ac("DRNG") is fully seeded or the sources stop
delivering (listing @lst:fv-seed-c). The model makes one collection and one
injection a step (listing @lst:fv-seed-pcal). The environment enters through
two choices: `yv`, the entropy each source credits, any amount up to what is
asked for, and `ok`, whether the seed callback succeeds. `Collect` and `InjOK`
(listing @lst:fv-env) restrict the choices only once the environment process
has turned `good`, which the liveness properties assume to happen. The
environment is bounded: time lets a reseed fall due `MaxDue` times, or with
`AnyDue` any number of times until it stops, and once every other process is
at rest (`Quiet`) only a stutter step of the environment is left, so that
the deadlock check reports every other state without a step. A collection
made without the lock of the #ac("DRNG") that an `esdm_reset` overtook is
`stale`: it is injected without credit, and the ghost value `gv` counts
nothing for a collection from before a reset. The switch
`CreditFailed` keeps the code before its fix: with `CreditFailed` set to
true, a failed injection still adds to `coll`, an addition the C code now
takes back.]

#figure(
```c
do {
    /* ... */
    reset_generation = atomic_load(&drng->reset_generation);
    esdm_get_seed_buffers(&seedbuf, &addtl, requested_bits, forced);
    if (lock) {
        mutex_w_lock(&drng->lock);
        do_full_init |= !atomic_load(&drng->fully_seeded);
        /* esdm_reset() since the collection began: no credit */
        stale = reset_generation !=
                atomic_load(&drng->reset_generation);
    }
    seed_entropy = stale ? 0 : esdm_entropy_rate_eb(&seedbuf);
    if (stale)
        collected_entropy = injected_entropy = 0;
    collected_entropy += seed_entropy;
    /* ... per source: collected_seedbuf, num_es_delivered ... */
    fully_seeded = !stale &&
                   esdm_fully_seeded(do_full_init, collected_entropy,
                                     &collected_seedbuf) &&
                   (!pr || do_full_init ||
                    collected_entropy >= requested_bits);
    if (!esdm_selftest_crypto_failed() &&
        esdm_drng_inject(drng, (uint8_t *)&seedbuf, sizeof(seedbuf),
                         (uint8_t *)&addtl, sizeof(addtl),
                         fully_seeded, drng_type)) {
        seeded = true;
        injected_entropy += seed_entropy;
        reached = fully_seeded;
    } else if (!stale) {
        collected_entropy -= seed_entropy;
        /* ... the same per source ... */
    }
    if (lock)
        mutex_w_unlock(&drng->lock);
} while (forced && !reached &&
         num_es_delivered >= es_delivered_threshold && /* ... */);
```,
  caption: [The emergency reseeding loop of `esdm_drng_seed_es`, abridged],
) <lst:fv-seed-c>

#figure(
```tla
se1: if (lockMode) await lock[sd] = NoProc;
     with (req = SeedReq(dfi, ~dfi /\ sd = PR),
           dfi2 = dfi \/ (lockMode /\ ~fs[sd]),
           yv \in Collect(req),       \* what each source credits
           ok \in InjOK,              \* drng_seed() succeeds or fails
           \* esdm_reset() since the collection began: no credit
           stale = ResetEpoch /\ lockMode /\ ep # resetGen[sd],
           y = IF stale THEN 0 ELSE SumSet(yv, ES),
           c = IF stale THEN 0 ELSE Min(coll + y, FCap + Osr),
           cv = IF stale THEN ZeroV ELSE AddV(collV, yv),
           full = FullTest(dfi2, c, cv) /\ (sd # PR \/ dfi2 \/ c >= req),
           again = forced /\ ~(ok /\ full) /\ Delivered(yv) >= thr,
           \* ghost: what the collection is worth, nothing if it was
           \* made before a reset
           gv = IF (IF lockMode THEN eg ELSE esGen) < resetGen[sd]
                THEN ZeroV ELSE yv,
           g = SumSet(gv, ES)
           \* ... seeded2, injd2 ...
           ) {
         if (ok) {                     \* esdm_drng_inject()
             viol := viol \cup CreditViol(sd, full, gv);
             goodSeed[sd] := IF full THEN Legit(sd, gv)
                             ELSE fs[sd] /\ goodSeed[sd];
             freshOut[sd] := Min(freshOut[sd] + g, FCap);
             \* ... freshES, used, due, force ...
             if (~fs[sd] /\ full) {
                 fs[sd] := TRUE;
                 initiated[sd] := TRUE;
             };
         } else {
             force[sd] := TRUE;
         };
         if (again) {                  \* the loop goes on
             dfi := dfi2;
             coll := IF ok \/ CreditFailed \/ stale THEN c ELSE coll;
             \* ... collV, seeded, injd, ep, eg ...
             goto se1;
         } \* ... else esdm_init_ops() and return ...
     };
```,
  caption: [One collection and injection, the step `se1` of the procedure
    `seedEs`, abridged],
) <lst:fv-seed-pcal>

#figure(
```tla
Collect(req) == IF good THEN {[x \in ES |-> req]}
                ELSE [ES -> {y \in Yield : y <= req}]
InjOK == IF InjectFail /\ ~good THEN BOOLEAN ELSE {TRUE}

process (e = "env")
{
en0: while (TRUE) {
         either {                              \* a reseed falls due
             await AnyDue \/ dues < MaxDue;
             with (d \in Nodes) due[d] := TRUE;
             if (~AnyDue) dues := dues + 1;
         } or {
             await Liveness /\ ~good;
             good := TRUE;                     \* the sources recover
         } or {
             await AnyDue;                     \* time stops
             goto enQ;
         } or {
             await ~AnyDue /\ Quiet;           \* the final state
         };
     };
enQ: \* ... the final state once the others are at rest ...
}
```,
  caption: [The environment of the reseeding model],
) <lst:fv-env>

#paragraph[Properties][A property that concerns the history of the state
uses ghost variables (listing @lst:fv-props). `freshOut` counts the entropy a
#ac("DRNG") received since its last output; an injection that declares a
#ac("DRNG") fully seeded without enough of it notes `CreditSinceOutput`, and
a generation from a #ac("DRNG") whose seed did not meet the seeding rule
notes `OutputUnseeded`, which the invariant `OutputFromSeeded` excludes.
`OperationalSound` and `AllSeededSound` refer to the state alone, the latter
admitting the windows of the steps in which the code lets the flag be wrong.
`RequestsReturn` is a liveness property: once the environment stays good and
time has stopped letting reseeds fall due (`Settled`), every request that
started returns. The liveness properties are checked against a specification
with weak fairness for each process and none for the environment (listing
@lst:fv-spec); the safety properties need no fairness.]

#figure(
```tla
\* in the step se1 of seedEs, as in listing above
viol := viol \cup CreditViol(sd, full, gv);
\* in the generation step of drngGet
viol := viol \cup (IF ~goodSeed[gd] THEN {"OutputUnseeded"} ELSE {});

CreditViol(d, full, yv) ==
    IF ~full THEN {}
    ELSE IF Ntg1 /\ Dfi(d)
    THEN IF Ntg1Full(AddV(freshES[d], yv)) THEN {} ELSE {"Ntg1Seed"}
    ELSE IF Min(freshOut[d] + SumSet(yv, ES), FCap) < Need(d)
    THEN {"CreditSinceOutput"} ELSE {}

OutputFromSeeded == "OutputUnseeded" \notin viol

OperationalSound == lock[0] = NoProc => (operational => fs[0])

AllSeededSound ==
    (allSeeded /\ \E d \in Nodes : ~fs[d]) =>
        \E p \in ProcSet : pc[p] \in {"us2", "na2", "ad1", "ad2", "ad3"}

Settled == <>[]good /\ (AnyDue => <>[](pc["env"] = "enQ"))

RequestsReturn ==
    Settled =>
        \A p \in Req : [](pc[p] \notin {"rq0", "Done"} => <>(pc[p] = "rq0"))
```,
  caption: [Properties of the reseeding model],
) <lst:fv-props>

#figure(
```tla
LiveSpec == /\ Init /\ [][Next]_vars
            /\ \A self \in Req : WF_vars(ReqStep(self))
            /\ \A self \in WorkerProcs : WF_vars(w(self) \/ noteAll(self))
            /\ \A self \in TaskProcs : WF_vars(TaskStep(self))
            /\ \A self \in MonProcs : WF_vars(MonStep(self))
            /\ \A self \in AdminProcs : WF_vars(AdminStep(self))
```,
  caption: [The specification of the liveness configurations with its
    fairness],
) <lst:fv-spec>

#paragraph[A configuration and its check][A configuration fixes the
constants and names the properties (listing @lst:fv-cfg). `CreditFailed`
checks the code before the fix of the credit of a failed seed operation: one
requester, the reseed worker, one source crediting 0, 128 or 256 bits, seed
operations that may fail. Its line `\* Expect:` tells `check.sh` that TLC has
to find a violation of `OutputFromSeeded`. With one worker, TLC finds it after
1,463 states and
prints the behavior leading to it (listing @lst:fv-trace): the task of the
reseed worker brings the initial #ac("DRNG") up; the first collection credits
128 bits, but the injection fails – and `coll` counts them nevertheless
(state 11); the second injects 128 bits, `coll` reaches the 256 bits of a
full seed, and the #ac("DRNG") is marked fully seeded, which the ghost
check notes as `CreditSinceOutput` (state 12); the request generates from it
(state 17).]

#figure(
```tla
\* The code before the fix: a failed injection's collection counts, so
\* an under-seeded DRNG serves
\* Expect: OutputFromSeeded
CONSTANTS
    NN = 2                \* the initial and one per-node DRNG
    Req = {"r1"}          \* one requester ...
    ReqKinds = {"nb"}     \* ... calling esdm_get_random_bytes
    SS = 2                \* units of 128 bits: 256 bits for a full seed
    Yield = {0, 1, 2}     \* a collection credits 0, 128 or 256 bits
    Worker = TRUE
    Tasks = {"t1"}
    InjectFail = TRUE     \* drng_seed() may fail
    CreditFailed = TRUE   \* the code before the fix
    \* ... the other constants ...
SPECIFICATION Spec
CHECK_DEADLOCK TRUE
INVARIANTS
    OutputFromSeeded
```,
  caption: [The configuration `CreditFailed`, abridged and annotated],
) <lst:fv-cfg>

#figure(
```console
$ TLC_WORKERS=1 tests/tla/check.sh EsdmReseed/CreditFailed.cfg
pass  EsdmReseed/CreditFailed.cfg (finds OutputFromSeeded, 1463 states)

Error: Invariant OutputFromSeeded is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
...
State 10: <sdA line 1249, col 14 to line 1286, col 53 of module EsdmReseed>
/\ fs = (0 :> FALSE @@ 1 :> FALSE @@ 2 :> FALSE)
/\ force = (0 :> TRUE @@ 1 :> FALSE @@ 2 :> FALSE)
/\ coll = [r1 |-> 0, t1 |-> 0, worker |-> 0, env |-> 0]
State 11: <se1 line 1107, col 14 to line 1217, col 40 of module EsdmReseed>
/\ fs = (0 :> FALSE @@ 1 :> FALSE @@ 2 :> FALSE)
/\ freshOut = (0 :> 0 @@ 1 :> 0 @@ 2 :> 0)
/\ coll = [r1 |-> 0, t1 |-> 1, worker |-> 0, env |-> 0]
State 12: <se1 line 1107, col 14 to line 1217, col 40 of module EsdmReseed>
/\ fs = (0 :> TRUE @@ 1 :> FALSE @@ 2 :> FALSE)
/\ freshOut = (0 :> 1 @@ 1 :> 0 @@ 2 :> 0)
/\ operational = TRUE
/\ viol = {"CreditSinceOutput"}
...
State 17: <dgN line 1875, col 14 to line 1941, col 59 of module EsdmReseed>
/\ viol = {"CreditSinceOutput", "OutputUnseeded"}
```,
  caption: [The check of `CreditFailed` and the trace TLC prints, abridged],
) <lst:fv-trace>

== Overview of the Models <sec:fv-overview>

Table @tab:fv-overview lists the models, the code each follows, the threads
and environment it consists of, and its configurations: how many there are,
how many of them expect a violation and thereby demonstrate one (a defect
before its fix, a seeded defect, or a behavior the code accepts), and the
largest state space checked.

#figure(
  table(columns: (auto, 1fr, 1.6fr, 1fr), align: left + horizon,
    table.header([Model], [Code], [Processes], [Configurations]),
    [`EsdmReseed` \ section @sec:fv-reseed], [`esdm/esdm_drng_mgr.c`, `esdm/esdm_es_mgr.c`, `esdm/esdm_es_events.c`], [Requesters of the five output calls, the reseed worker and its tasks, the #ac("ES") monitor, an administrator, the environment], [41, 9 demonstrating; largest 105,996,577 states],
    [`EsdmSelftest` \ section @sec:fv-selftest], [`esdm/esdm_selftest.c` and its callers], [Initialization, requests with and without blocking, seed callers, the #ac("RPC") self test, the reseed worker, the periodic worker, reinitialization, finalization, the environment], [19, 9 demonstrating; largest 264,807 states],
    [`EsdmAuxPool` \ section @sec:fv-aux], [`esdm/esdm_es_aux.c`], [Writers with and without entropy, seedings extracting, readers of the need for entropy, reinitialization, the environment], [25, 14 demonstrating; largest 934,668 states],
    [`EsdmShmStatus` \ section @sec:fv-shm-status], [`esdm/esdm_shm_status.c`, its readers], [The publishing threads of the server, the thread setting the threshold, the signal handler and the event thread, server start, exit and restart, the poll checkers of both #ac("CUSE") daemons, aux clients], [40, 16 demonstrating; largest 2,904,036 states],
    [`EsdmCuse` \ section @sec:fv-cuse], [`frontends/cuse/`], [Polling and reading threads, the #ac("FUSE") workers and the kernel, the poll checker, the server], [37, 14 demonstrating; largest 6,218,589 states],
    [`EsdmEgd` \ section @sec:fv-egd], [`service-egd/server/esdm_egd_server.c`], [The worker, clients of both sockets, the generators], [29, 13 demonstrating; largest 2,272,766 states],
    [`EsdmSupervisor` \ section @sec:fv-supervisor], [`common/linux_support.c` and its callers], [The supervisor, the daemon, senders of signals], [25, 18 demonstrating; largest 239,648 states],
    [`EsdmRpcServer` \ section @sec:fv-rpc-server], [`service-rpc/server/esdm_rpc_server.c`, the thread pool], [The main thread, the unprivileged interface thread, its workers, clients, termination signals, `esdm_fini`], [37, 12 demonstrating; largest 49,696,012 states],
    [`EsdmRpcClient` \ section @sec:fv-rpc-client], [`service-rpc/client/`], [Client threads of the calls for random bytes and of a call not re-sent, the server per connection, interrupts, deadlines, the teardown], [28, 8 demonstrating; largest 7,005,733 states],
    [`EsdmKernelEs` \ section @sec:fv-kernel-es], [`kernel/esdm_es/`: `esdm_es_ring.c`, `esdm_health.c`, `esdm_es_drbg.c`], [The interrupt and scheduler hooks per #ac("CPU") with nested interrupts, the #ac("IOCTL") readers, notifier resets, module exit], [32, 16 demonstrating; largest 125,689,609 states],
    [`EsdmKernelCdev` \ section @sec:fv-kernel-cdev], [`kernel/esdm_cdev/esdm_cdev_main.c`], [Readers and pollers of the three devices, the watcher, the wake work of `/dev/esdm_pr`, the #ac("ESDM"), signals], [20, 6 demonstrating; largest 2,336,957 states],
    [`EsdmKernelCdevConn` \ section @sec:fv-kernel-cdev-conn], [`kernel/esdm_cdev/esdm_cdev_egd.c`], [Tasks calling `esdm_cdev_invoke`, the connect work, the #ac("ESDM") with restarts and closes, signals, timeouts], [31, 14 demonstrating; largest 61,155,842 states],
  ),
  caption: [The models of the #ac("ESDM")],
) <tab:fv-overview>

== The Models <sec:fv-models>

=== DRNG Reseeding and Output <sec:fv-reseed>

`tests/tla/EsdmReseed.tla` models `esdm/esdm_drng_mgr.c` together with the
seeding state of `esdm/esdm_es_mgr.c` (sections @sec:seeding and
@sec:not-fully-seeded).

#paragraph[Model][The model contains the initial #ac("DRNG"), one per-node
#ac("DRNG") and the prediction resistance #ac("DRNG"), each with its lock,
its seed lock, its fully seeded and force reseed flags, its count of resets
and its output since the last full seed. Concurrent processes call
`esdm_get_random_bytes_full`, `esdm_get_random_bytes_full_noblock`,
`esdm_get_random_bytes`, `esdm_get_random_bytes_pr` and
`esdm_get_random_bytes_pr_noblock`; the reseed worker starts reseeds and
bring-ups on its task threads; the #ac("ES") monitor seeds through
`esdm_drng_seed_work_try`; an administrator calls `esdm_drng_force_reseed`
and, as the thread of `esdm/esdm_es_events.c` does after a change of the
#ac("VM") generation (section @sec:vm-clone), `esdm_reset` followed by
`esdm_force_fully_seeded_all_drbgs`; the environment lets reseeds fall due.
A reseed interval of zero seconds, with which every request reseeds its
#ac("DRNG") first, is a mode a configuration selects. Every entropy source
credits any amount up to the amount requested, including none, in every
collection, and a seed operation may fail: a Jitter #acs("RNG") as the only
source that fails or delivers too little at any time is one of the behaviors
checked.]

#paragraph[NTG.1][With the build option `ais2031_ntg1`, the model has two
entropy sources and applies the rule of `esdm_fully_seeded`: a #ac("DRNG")
that is not fully seeded becomes fully seeded with 240 bits of entropy from
each of two sources, or from the Jitter #acs("RNG") alone where it is NTG.1
conformant by itself (`es_jent_ntg1`); the emergency reseeding continues
while two sources deliver.]

#paragraph[Abstractions][The model counts the entropy of the seeds, not the
length of the seed material, which is the larger of the two: every source
fills its share of the seed buffer with the data of the amount asked for –
at least the security strength of 256 bits – and credits the entropy it
estimates in it. Entropy is counted in units of 128 bits, of 64 bits with the
#ac("SP") 800-90C oversampling and of 16 bits for NTG.1; output in units of
$2^15$ bits. The reseed interval and the request counter are modeled as one
flag, which the environment raises. A pass of the reseed worker is one step,
without its waits and retry backoffs, and a pass that would start nothing is
no step. A collection and the injection that follows it are one step; for the
two seedings that collect without the lock of the #ac("DRNG") – the reseed of
a fully seeded #ac("DRNG") and the forced reseed of one that used up its
output – the model records when the collection began. The reseed interval is
read once per request where the code reads it twice, and it does not change
within a configuration. The model omits the limit of $2^30$ generate
operations, `esdm_get_seed`, the shutdown, the allocation of the #ac("DRNG",
pl: true) and the self test gate, which section @sec:fv-selftest covers.]

#paragraph[Reset][`esdm_reset` voids the entropy collected before it, as a
clone of the #ac("VM") holds the same. The ghost counters of the entropy
injected since the last output are reset with each #ac("DRNG"), and a
collection made before the entropy sources were reset counts as no entropy
once the #ac("DRNG") it is injected into has been reset. The properties
`CreditSinceOutput`, `OutputFromSeeded` and `PROutput` thereby also state
that no #ac("DRNG") is fully seeded, and none serves, with entropy of before
a reset.]

#paragraph[Final state and deadlocks][The environment is bounded: every
requester may stop after any of its calls, and time lets a reseed fall due at
most once – in some configurations not at all – or, in `QuickPR`, `QuickNtg1`, `NoWorker`, `Unbudgeted`, `PR`, `Ntg1Two`, `Ntg1Jent`, `Noblock` and `LiveStarved`, any number
of times until it stops. Once all of it
has stopped, the model comes to rest in the state `Quiet` – requesters and
administrator done, the worker, its tasks and the monitor waiting for work –
where only a stuttering step of the environment is left. TLC checks every
configuration for deadlocks: any other state without a step, such as a
thread that waits for a lock nobody releases or a blocking request that
waits for a seeding nobody attempts, is reported. The check does not see a
thread that waits while others keep running; the liveness properties cover
that.]

#paragraph[Liveness][The liveness properties are checked with the
specification `LiveSpec` of the module: weak fairness for every requester,
the worker, every task thread, the monitor and the administrator, each over
all steps of the process including the procedures it calls, and no fairness
for the environment. The specification the translator generates states
strong fairness per procedure; TLC cannot handle that many conditions in a
liveness check, and the weaker assumption suffices in every configuration
that checks liveness. These configurations have one requester: requesters
that take a lock from each other without end, which a fair lock excludes,
are not covered. Every property assumes that the entropy sources eventually
deliver for good – every collection credits what is asked for, no seed
operation fails, a Jitter #acs("RNG") collector is free – and that eventually
no further reseed falls due by time. `AllEventuallySeeded` and
`SpentReseeded` assume in addition a task thread per #ac("DRNG") or requests
that eventually stop; the open observations below give the reason.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`OutputFromSeeded`], [Every chunk of the initial or a per-node
      #ac("DRNG") comes from a seed that met the seeding rule with entropy
      injected after the previous output and the last reset of that
      #ac("DRNG"): an #ac("ESDM") that is not fully seeded – its sources
      failing or delivering too little – outputs nothing.],
    [`CreditSinceOutput`], [A #ac("DRNG") is marked fully seeded only when the
      entropy injected since its last output and reset reaches the security
      strength, or the initial seed size when it was not fully seeded – with
      `ais2031_ntg1` the latter is `Ntg1Seed`: no output splits an emergency
      reseeding that adds up collections.],
    [`Ntg1Seed`], [With `ais2031_ntg1`, a #ac("DRNG") becomes fully seeded
      only with 240 bits of entropy from each of two sources, or from an
      NTG.1 Jitter #acs("RNG"), since its last output, in seed material of at
      least 256 bits.],
    [`PROutput`], [A chunk of the prediction resistance #ac("DRNG") is no
      larger than the entropy injected for it, less the oversampling.],
    [`OutputBound`, `ChunkBound`], [The output of a per-node #ac("DRNG")
      since its last seed that met the seeding rule – counted by a ghost
      variable, not by the counter of the code – stays below
      `drng_max_reseed_bits` plus one chunk, as no generate operation starts
      at or beyond `drng_max_reseed_bits`; the initial #ac("DRNG") stops at
      its budget. The counter of the code obeys the same bounds.],
    [`ReseedPerRequest`], [With a reseed interval of zero seconds, a blocking
      request seeds the initial or per-node #ac("DRNG") before every chunk it
      takes from it. The seeding may collect too little.],
    [`OperationalSound`], [The #ac("ESDM") is operational only while the
      initial #ac("DRNG") is fully seeded, whenever its lock is free.],
    [`OperationalComplete`], [A fully seeded initial #ac("DRNG") makes the
      #ac("ESDM") operational, except within a seeding that takes the lock for
      each injection.],
    [`AllSeededSound`], [The flag that all #ac("DRNG", pl: true) are fully
      seeded is wrong only within the windows of `esdm_unset_fully_seeded`,
      `esdm_drngs_note_all_seeded` and `esdm_reset`.],
    [`FullComplete`], [A blocking request returns all data requested.],
    [`PRInitiated`], [The prediction resistance #ac("DRNG") serves only after
      its initial full seed.],
    [`LocksReleased`], [No thread returns from a call, waits for work or ends
      while it holds a lock of a #ac("DRNG"), a seed lock or the lock of the
      prediction resistance requests.],
    [`TaskAccounting`], [The counters of the reseed worker equal the number
      of its running tasks, of its bring-ups and the reseeds marked as
      running.],
    [`QuietSeeded`], [In the final state no lock is held and, with a reseed
      worker, every #ac("DRNG") serving requests is fully seeded, has output
      left and – unless every request reseeds – is not due for a reseed, and
      the #ac("ESDM") is operational.],
    [Deadlock freedom], [Every state without a step is the final state.],
    [`EventuallyOperational`], [Liveness: the #ac("ESDM") becomes operational
      and stays so.],
    [`RequestsReturn`], [Liveness: every call for random bytes returns.],
    [`AllEventuallySeeded`], [Liveness, with a task thread per #ac("DRNG") or
      once the requests stop: all #ac("DRNG", pl: true) serving requests are
      noted as fully seeded again and again.],
    [`SpentReseeded`], [Liveness, with a task thread per #ac("DRNG") or once
      the requests stop: a #ac("DRNG") that used up its output is reseeded or
      leaves the fully seeded state.],
  ),
  caption: [Properties of the reseeding and output model. The liveness
    properties hold once the entropy sources deliver and no further reseed
    falls due by time.],
) <tab:fv-reseed-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Run], [Result], [States]),
    [`QuickDrg4`], [Small scope: DRG.4 bit limits, the reseed worker, `esdm_get_random_bytes_full` and `esdm_get_random_bytes`], [default], [holds], [2,182,383],
    [`QuickNoblock`], [Small scope: `esdm_get_random_bytes_full_noblock` and the reseed worker], [default], [holds], [965,563],
    [`QuickPR`], [Small scope: prediction resistance requests, failing seed operations], [default], [holds], [695,464],
    [`QuickNtg1`], [Small scope: NTG.1 with two sources, no bit limits], [default], [holds], [169,220],
    [`QuickPerRequest`], [Small scope: a reseed interval of zero seconds, blocking requests], [default], [holds], [942,308],
    [`QuickReset`], [Small scope: `esdm_reset` and the seeding after it next to a request that reseeds the spent initial #ac("DRNG")\; initial seed larger than a reseed], [default], [holds], [154,290],
    [`QuickResetTwo`], [Small scope: `esdm_reset` and the seeding after it with a per-node #ac("DRNG") next to a request, no reseed worker], [default], [holds], [932,547],
    [`QuickResetPR`], [Small scope: `esdm_reset` next to non-blocking prediction resistance requests], [default], [holds], [62,383],
    [`QuickResetFull`], [Small scope: `esdm_reset` next to a blocking request and the reseed worker], [default], [holds], [2,797,039],
    [`QuickNoWorker`], [Small scope: no reseed worker, two requesters take the initial #ac("DRNG") out of the fully seeded state under each other; initial seed larger than a reseed], [default], [holds], [778,709],
    [`LiveWorker`], [Liveness: a blocking requester, the initial #ac("DRNG"), the reseed worker], [default], [holds], [59,678],
    [`LiveMonitor`], [Liveness: a blocking requester, the initial #ac("DRNG"), the #ac("ES") monitor, no reseed worker], [default], [holds], [7,500],
    [`LiveNode`], [Liveness: a non-blocking requester uses up the per-node #ac("DRNG"), the reseed worker], [default], [holds], [43,464],
    [`LivePR`], [Liveness: prediction resistance requests, the reseed worker], [default], [holds], [22,216],
    [`LiveReset`], [Liveness: after `esdm_reset` the reseed worker seeds both #ac("DRNG", pl: true) again; no requester], [default], [holds], [12,560],
    [`Drg4`], [DRG.4 bit limits, the reseed worker, both calls, a source short at any time, both request sizes], [slow], [holds], [14,701,046],
    [`NoWorker`], [No reseed worker: requests and the #ac("ES") monitor seed, failing seed operations], [slow], [holds], [33,577,662],
    [`NoWorkerTwo`], [No reseed worker: two requesters take the per-node #ac("DRNG") out of the fully seeded state under each other], [slow], [holds], [52,118,531],
    [`Unbudgeted`], [No bit limits (default build): reseeds by interval and `esdm_drng_force_reseed`], [slow], [holds], [9,272,668],
    [`Admin`], [`esdm_reset` with the seeding after it and `esdm_drng_force_reseed` at any time, the reseed worker. With a source short at any time and failing seed operations in addition, the check did not complete: 50,289,167 states without a violation], [slow], [holds], [94,182,361],
    [`ResetWorker`], [`esdm_reset` next to the reseed of a spent per-node #ac("DRNG")\; initial seed larger than a reseed], [slow], [holds], [25,361,865],
    [`ResetPR`], [`esdm_reset` next to prediction resistance requests, blocking and not, and the reseed worker], [slow], [holds], [15,441,031],
    [`TwoReq`], [Two blocking requesters on the per-node and the initial #ac("DRNG")], [slow], [holds], [105,996,577],
    [`PR`], [Prediction resistance requests, blocking and not, failing seed operations], [slow], [holds], [2,216,024],
    [`Osr`], [#ac("SP") 800-90C oversampling: initial seed and the RBG3(RS) prediction resistance #ac("DRNG")], [slow], [holds], [28,097,919],
    [`Ntg1Two`], [NTG.1 seeding strategy with two sources of 240 bits of entropy], [slow], [holds], [23,657,432],
    [`Ntg1Jent`], [NTG.1 seeding strategy with an NTG.1 Jitter #acs("RNG")], [slow], [holds], [26,753,664],
    [`ThreshMaxFixed`], [`drng_reseed_threshold_bits` equal to `drng_max_reseed_bits`: two blocking requests and the initial #ac("DRNG") that stops the #ac("ESDM")], [slow], [holds], [22,364,518],
    [`PerRequest`], [A reseed interval of zero seconds, blocking and non-blocking requests], [slow], [holds], [3,798,296],
    [`Noblock`], [Both non-blocking calls for random bytes], [slow], [holds], [4,823,980],
    [`Liveness`], [Liveness: blocking and non-blocking requests on the per-node and the initial #ac("DRNG"), the reseed worker], [slow], [holds], [522,232],
    [`LiveTwoTasks`], [Liveness: a task thread per #ac("DRNG"), a non-blocking requester uses up both without end; `SeededUnderLoad` holds as well], [slow], [holds], [852,526],
    [`CreditFailed`], [The code before the fix of the credit of a failed seed operation], [default], [finds \ `OutputFromSeeded`], [1,576],
    [`PRInitiated`], [Before the fix: the prediction resistance #ac("DRNG") serving before its initial NTG.1 seed], [default], [finds \ `PRInitiated`], [10,163],
    [`ThreshMax`], [Before the fix: a blocking request failing when the initial #ac("DRNG") stops the #ac("ESDM")], [default], [finds \ `FullComplete`], [878,549],
    [`ResetStale`], [Before the fix: a collection begun before `esdm_reset` credited after it], [default], [finds \ `CreditSinceOutput`], [4,639],
    [`ResetOrder`], [Before the fix: `esdm_reset` resetting the #ac("DRNG", pl: true) before the entropy sources], [default], [finds \ `CreditSinceOutput`], [256],
    [`CounterReset`], [A defect the code does not have: every injection resets the output count], [default], [finds \ `OutputBound`], [4,750],
    [`NoSeeder`], [Neither reseed worker nor #ac("ES") monitor: a blocking request waits for good], [default], [finds a \ deadlock], [57],
    [`LiveStarved`], [One task thread, two #ac("DRNG", pl: true), reseeds falling due without end], [default], [finds \ `BringupNotStarved`], [247,496],
    [`LiveLoad`], [One task thread, two #ac("DRNG", pl: true), requests using up the initial #ac("DRNG") without end], [default], [finds \ `SeededUnderLoad`], [6,395],
  ),
  caption: [Configurations of the reseeding and output model and their
    results. The default run of `check.sh` leaves the slow
    ones out. Where TLC finds a violation, the states are those found until
    then; their number varies from run to run.],
) <tab:fv-reseed-results>

#paragraph[Guards][Each of the following guards was removed from a scratch
copy of the model, one at a time; a configuration of the default run then
fails, which shows that the configurations exercise the guard:]

#figure(
  table(columns: (1fr, auto, auto), align: left + horizon,
    table.header([Removed from the model], [Configuration], [Violated]),
    [The fully seeded state read again under the lock by the forced reseed of
      a #ac("DRNG") that used up its output (`do_full_init` in
      `esdm_drng_seed_es`)], [`QuickReset`], [`CreditSinceOutput`],
    [The same in the reseed that collects without the lock
      (`esdm_drng_reseed_seed_locked`)], [`QuickNoWorker`],
      [`CreditSinceOutput`],
    [The check of the fully seeded state under the lock before every chunk
      (`esdm_drng_get`)], [`QuickReset`], [`OutputFromSeeded`],
    [The collections of before a reset taken out of the sum of the forced
      reseed], [`QuickReset`], [`CreditSinceOutput`],
    [The second wait of a blocking request (`FullRetry` switched off)],
      [`QuickResetFull`], [`FullComplete`],
    [The flag of all fully seeded #ac("DRNG", pl: true) cleared at the end of
      `esdm_reset`], [`QuickResetTwo`], [`AllSeededSound`],
    [A reseed left to the worker with a reseed interval of zero seconds],
      [`QuickPerRequest`], [`ReseedPerRequest`],
    [The reseed of a #ac("DRNG") that used up its output by the worker, with a
      reseed interval of zero seconds], [`QuickPerRequest`], [`QuietSeeded`],
    [The bring-ups of the worker], [`QuickNoblock`, `LiveWorker`],
      [`QuietSeeded`, deadlock],
    [The release of the seed lock in `esdm_drng_get_reseed`],
      [`QuickReset`], [`LocksReleased`],
    [The release of the seed lock in `esdm_drng_reseed_one`],
      [`QuickNoblock`], [`LocksReleased`],
    [The release of the lock of the #ac("DRNG") in `esdm_drng_seed`],
      [`QuickReset`], [`LocksReleased`],
    [The release of the lock of the prediction resistance requests],
      [`QuickPR`], [`LocksReleased`],
    [The decrement of the count of running tasks], [`QuickNoblock`],
      [`TaskAccounting`],
  ),
  caption: [Guards removed from a copy of the reseeding and output model and
    the configuration of the default run that fails without them],
) <tab:fv-reseed-guards>

The count of the output that only a full seed resets is guarded by
`OutputBound` through its ghost counter: `CounterReset` switches a reset by
every injection on and fails. One removal passes every configuration: without
the `esdm_force_fully_seeded_all_drbgs` that follows `esdm_reset`, the reseed
worker, the #ac("ES") monitor and the next request seed the #ac("DRNG",
pl: true) all the same. No property requires that the thread handling the
event seeds them itself; with too little entropy at that moment it does not.

#paragraph[Findings][Five defects are fixed, and the configurations named
keep the code before each fix. Model checking found the first two and the
last two:]

- `esdm_drng_seed_es` adds a collection to the entropy it counts towards the
  fully seeded level, in all and per source, before `esdm_drng_inject` hands
  it to the seed callback of the #ac("DRNG"). When the callback fails, the
  next injection of the emergency reseeding counts entropy the #ac("DRNG")
  never received: a #ac("DRNG") without a full seed – 128 bits collected and
  lost, 128 bits injected – is marked fully seeded and serves output
  (configuration `CreditFailed`, property `OutputFromSeeded`). The defect
  required a failing seed callback. `esdm_drng_seed_es` now takes the counts
  of a failed injection back; `CreditFailed` keeps the code before the fix to
  show that the properties catch it.
- The prediction resistance #ac("DRNG") served from the entropy collected for
  a request, less the oversampling, also before its initial seed reached the
  fully seeded level – with `ais2031_ntg1`, entropy from one source
  (`PRInitiated`), though never more than the fresh entropy (`PROutput`).
  Like every #ac("DRNG"), it now serves only once fully seeded; until then,
  each request tries the initial full seed again.
- A blocking request failed with `-EOPNOTSUPP` when the initial #ac("DRNG")
  stopped the #ac("ESDM") between the wait of the request for the operational
  state and its generation, as it does with `drng_reseed_threshold_bits`
  equal to `drng_max_reseed_bits` or on `esdm_reset` (`ThreshMax`,
  `FullComplete`). `esdm_get_random_bytes_full` now waits again.
- `esdm_reset` reset the #ac("DRNG", pl: true) before the entropy sources. The
  reset of the initial #ac("DRNG") wakes the #ac("ES") monitor, and a seeding
  between the two steps – the monitor, a bring-up of the reseed worker, a
  request – collected what the sources still credited, such as the content of
  the auxiliary pool of before the clone, and marked a #ac("DRNG") that was
  reset already fully seeded with it (`ResetOrder`, `CreditSinceOutput`).
  `esdm_reset` now resets the entropy sources first.
- The reseed of a fully seeded #ac("DRNG") and the forced reseed of one that
  used up its output collect without the lock of the #ac("DRNG"). A
  collection begun before `esdm_reset` and injected after it counted in full,
  and the forced reseed added it to its collections of before the reset: the
  #ac("DRNG") was marked fully seeded again with entropy a clone holds as
  well (`ResetStale`, `CreditSinceOutput`). Without oversampling, where the
  initial seed is as large as a reseed, one such collection sufficed. A
  #ac("DRNG") now counts its resets; a seeding reads the count before it
  collects and under the lock, and a collection of before a reset is injected
  without credit.

#paragraph[Open observations][Two behaviors the model shows are left as they
are; the configurations demonstrate them:]

- Without a reseed worker and without the #ac("ES") monitor – a process that
  uses the library without `esdm_init_monitor` – a blocking request seeds
  once and then waits for the operational state. When that seeding collected
  too little, nothing seeds again until another request arrives: the request
  waits also after the sources recover (`NoSeeder`, a deadlock of the model).
- The reseed worker starts the reseeds that are due before the bring-ups, the
  reseed of the initial #ac("DRNG") last. With fewer task threads – Jitter
  #acs("RNG") collectors – than #ac("DRNG", pl: true), reseeds that fall due
  again and again take every free thread: the initial #ac("DRNG") is not
  brought up while reseeds of the per-node #ac("DRNG", pl: true) fall due
  faster than they complete (`LiveStarved`), and a per-node #ac("DRNG") is
  not brought up while requests use up the initial #ac("DRNG") again and
  again (`LiveLoad`). The model leaves the retry backoffs of the worker out;
  they delay the next reseed of a #ac("DRNG") that is still due when its
  reseed ends, not of one that falls due after that. The liveness properties
  therefore assume that reseeds stop
  falling due by time, and those about every #ac("DRNG") being seeded or
  reseeded in the end – `AllEventuallySeeded`, `SpentReseeded` – a task
  thread per #ac("DRNG") or requests that stop.

=== Self Test Gate <sec:fv-selftest>

`tests/tla/EsdmSelftest.tla` models `esdm/esdm_selftest.c` and its callers:
the verdict of the crypto self tests, the periodic self test worker, the
gate `esdm_selftest_crypto_passed` in `esdm_drng_get` and `esdm_get_seed`,
the checks of the verdict in the seedings and the wait of the blocking
callers (section @sec:self-tests).

#paragraph[Model][`esdm_init` runs the self tests in the #ac("DRNG") manager,
seeds where the entropy sources deliver, and runs the initial pass; requests
call `esdm_drng_get`, whose entry starts the periodic worker, and generate
chunks under the #ac("DRNG") lock; blocking requests
(`esdm_get_random_bytes_full`) first wait in
`esdm_drng_sleep_while_nonoperational` for the #ac("ESDM") to become
operational; callers of `esdm_get_seed` collect and hand out; the privileged
#ac("RPC") self test runs `esdm_selftest_run`; the reseed worker and the
waiting requests seed under the #ac("DRNG") lock; `esdm_reinit` reruns the
tests and replaces the #ac("XOF") contexts of the auxiliary pool; `esdm_fini`
stops the worker, joins it and releases the #ac("DRNG", pl: true). The
environment may break the crypto implementations once at any time, after
which every self test of them fails.]

#paragraph[Steps][The verdict is an atomic variable that `esdm_selftest_record` writes under no
lock. Every reader therefore checks it in one step and acts on it in a later
one, as the code does in separate statements: the check before a chunk, its
generation, the check after it and its handing out are four steps, and so are
the entry check of a seeding, its collection, the check before the injection
and the injection. A failure can be recorded between any two of them. The
ghost variables that record a violation are set in a step other than the one
that makes the check.]

#paragraph[Abstractions][One #ac("DRNG") lock stands for the lock of whichever
#ac("DRNG") a thread takes; the node cleanup lock is reader-preferring. The
generation of a chunk and a collection are one step each, the moment they end.
The #ac("ESDM") becomes operational in `esdm_init` or with the first injection
after entropy arrived, which it does once and at some time, and stays
operational. `thread_wait_event` polls its condition every 100 ms and is
modeled as a step the condition enables;
`esdm_drng_sleep_while_not_all_nodes_seeded` has the shape of the modeled
wait and is not modeled separately. The
waits of the worker are one wait until a pass is due or the worker is asked
to leave. The worker has one thread slot, for which `thread_start` waits;
`thread_start` may fail. Of the entropy source self tests only
`esdm_aux_selftest` is modeled. The release of the #ac("DRNG") state in
`esdm_fini` is not modeled. The crypto callbacks are set when a
#ac("DRNG") is allocated and never replaced at run time:
`esdm_crypto_cb_update` is the lock of `esdm_drngs_node_alloc`.]

#paragraph[Deadlock and liveness][The deadlock check is on in every
configuration. Every thread but the periodic worker is bounded, and the
environment acts a bounded number of times unless a worker is on duty; once
every bounded thread returned and no worker is on duty, the environment
idles, which is the only state without a further step that the model
admits. While a worker is on duty the model keeps stepping, so a thread that
hangs then is no deadlock to the model checker: it violates `Progress`, which
every configuration with a thread pool that models the current code lists.
All processes are weakly fair.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`OutputGated`], [Every chunk and every seed handed out was generated or
      collected while the verdict of the crypto self tests stood passed:
      neither before they ran nor after a failure was recorded.],
    [`GenerateGated`, `EntryGated`], [No chunk is generated once a failure
      was recorded before the request took the #ac("DRNG") lock for it. A
      request that found a failure recorded when it took the #ac("DRNG")
      instances starts no worker and takes no #ac("DRNG") lock; such a call of
      `esdm_get_seed` collects nothing.],
    [`VerdictFinal`], [The verdict moves from undone to passed or failed and
      from passed to failed only.],
    [`FailureKept`], [A recorded failure is never lost to a concurrent passing
      run.],
    [`WorkerMarked`, `StartWaitsForLeaving`], [At most one periodic worker
      runs, and a request waits in `thread_start` only for a worker on its way
      out.],
    [`LateWorkerIdle`], [A worker that starts after the request to leave runs
      no self test pass.],
    [`NoCryptoAfterFailure`], [No seeding collects once a failure was recorded
      before it took the #ac("DRNG") lock, none injects once a failure was
      recorded before its collection ended, and the reseed worker starts none
      once a failure was recorded before its previous seeding ended.],
    [`WaitGated`], [A blocking request that found a failure recorded when it
      began or ended its wait returns without a seeding and without a
      request.],
    [`EsVerdictSound`], [An entropy source self test fails only for a broken
      source.],
    [`Progress`], [Every thread but the worker finishes: no deadlock between
      the #ac("DRNG") lock, the node cleanup lock, the thread slot and the
      join in `esdm_fini`, and no blocking request left waiting for an
      #ac("ESDM") that a failure or `esdm_fini` keeps from becoming
      operational.],
    [`PeriodicRuns`, `WorkerOnDuty`], [A request that passed the gate leaves a
      worker on duty, which repeats the self tests as long as nothing breaks
      and the worker is not stopped.],
    [`FailureStopsWorker`, `StopLeaves`], [After a failure, or once asked to
      stop, the worker leaves permanently.],
    [`NoOutputAfterFailure`, `NoInjectAfterFailure`, `NoStartAfterJoin`],
      [Not delivered by the code, and expected to fail: no chunk or seed is
      handed out, and no injection made, at a moment after a failure was
      recorded; no worker starts after the join in `esdm_fini`.],
  ),
  caption: [Properties of the self test gate model],
) <tab:fv-selftest-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`GateEachChunk`], [The verdict checked before and after every chunk and before a seed is handed out, the implementations breaking], [holds], [79,908],
    [`GateSeeding`], [Seedings and the reseed worker stopping on a recorded failure], [holds], [29,883],
    [`Periodic`], [The periodic self tests, one worker repeating its passes], [holds], [42,858],
    [`ThreadFail`], [`thread_start` failing, requests restarting the worker], [holds], [10,334],
    [`Fini`], [`esdm_fini` with the worker, a request and the reseed worker; a worker started after the join], [holds], [17,866],
    [`EsLocked`], [The auxiliary pool self test reading under the pool lock], [holds], [303],
    [`Wait`], [A blocking request waiting for the first seed, a failure recorded meanwhile], [holds], [50,727],
    [`WaitWorker`], [As `Wait`, the failure recorded by the periodic worker], [holds], [43,900],
    [`WaitFini`], [A blocking request waiting for a seed that never comes, `esdm_fini` ending the wait], [holds], [5,390],
    [`TwoRequests` (slow)], [Two requests of two chunks and the #ac("RPC") self test, the implementations breaking], [holds], [264,807],
    [`Gate`], [Before the fix: a failure recorded while a request generates], [finds `OutputGated`], [5,186],
    [`GateWindow`], [Before the fix: a failure recorded between the check under the #ac("DRNG") lock and the generation], [finds `OutputGated`], [5,330],
    [`SeedGate`], [Before the fix: a failure recorded while `esdm_get_seed` collects], [finds `OutputGated`], [1,530],
    [`ReseedAfterFailure`], [Before the fix: the reseed worker after a failure], [finds `NoCryptoAfterFailure`], [532],
    [`WaitHang`], [Before the fix: a request waiting for a seeding that a failure stopped], [finds a deadlock], [12,919],
    [`ReinitRace`], [Before the fix: the #ac("XOF") context replaced during a self test pass], [finds `EsVerdictSound`], [614],
    [`HandoutWindow`], [Current code: a failure recorded after the check that follows the generation], [finds `NoOutputAfterFailure`], [5,461],
    [`InjectWindow`], [Current code: a failure recorded after the check before the injection], [finds `NoInjectAfterFailure`], [1,063],
    [`StartAfterJoin`], [Current code: a request starting the worker after the join in `esdm_fini`], [finds `NoStartAfterJoin`], [663],
  ),
  caption: [Configurations of the self test gate model and their results.
    For a configuration that finds a violation, the number of states is the
    one reached when the search stopped, which varies between runs.],
) <tab:fv-selftest-results>

#paragraph[Checks of the guards][Each check of the verdict in the model was
removed in turn in a copy of the model, and a configuration of the table
then fails: the check under the #ac("DRNG") lock (`GateEachChunk`, by
`GenerateGated`), the check after the generation and the one before a seed is
handed out (`GateEachChunk`, `OutputGated`), the entry checks of
`esdm_drng_get` and `esdm_get_seed` (`GateEachChunk`, `EntryGated`), the
three checks of a seeding and of the reseed worker (`GateSeeding`,
`NoCryptoAfterFailure`), the checks before and after the wait (`Wait`,
`WaitGated`), the failure and the termination in the condition of the wait
(`Wait`, `WaitWorker` and `WaitFini`, each by a deadlock), the stop request
in the loop of the worker (`Fini`, `LateWorkerIdle`), its leaving after a
failure (`ThreadFail`, a liveness property), the compare and exchange of
a passing verdict (`GateEachChunk`, `FailureKept`) and the pool lock in
`esdm_aux_selftest` (`EsLocked`, `EsVerdictSound`). Without the idle step of
the environment, `GateEachChunk` reports a deadlock: the check is effective
there.]

#paragraph[Results][The verdict is final, no failure is lost, nothing
generated or collected before the first pass or after a recorded failure is
handed out, at most one worker runs, repeats its passes and leaves after a
failure or when stopped, a blocking request returns after a failure, and
nothing deadlocks. The findings, all fixed since, are:]

- `esdm_drng_get` checked the verdict once, at its entry, and generated the
  whole request in chunks without checking again; `esdm_get_seed` checked it
  before a collection that may wait for entropy. A failure recorded meanwhile
  – even by a pass that detected it before the request passed the gate – did
  not stop the request (`Gate`, `SeedGate`, `OutputGated`). `esdm_drng_get`
  now checks the verdict under the #ac("DRNG") lock before every chunk, and
  `esdm_get_seed` after its collection, before the seed is handed out
  (`GateEachChunk`).
- The check under the #ac("DRNG") lock and the generation are two statements,
  and the verdict is not written under that lock: a failure recorded between
  them did not stop the chunk, so that one chunk for each request in flight
  could be generated after the failure and handed out (`GateWindow`,
  `OutputGated`). `esdm_drng_get` now checks the verdict again after the
  generation and wipes the chunk (`GateEachChunk`).
- A failure did not stop the reseed worker: `esdm_drng_reseed_stop` considered
  termination only, so the seedings kept collecting entropy and injecting
  it with the failed implementations, though nothing was output
  (`ReseedAfterFailure`, `NoCryptoAfterFailure`). A recorded failure – not
  the tests that have not run yet – now ends the reseed worker, skips every
  seeding and, checked again under the #ac("DRNG") lock, every injection
  (`GateSeeding`). The callers waiting for the #ac("ESDM") to become
  operational or fully seeded would then have waited for a seeding that no
  longer takes place (`WaitHang`); a recorded failure ends their wait
  (`Wait`, `WaitWorker`).
- `esdm_aux_selftest` read the #ac("XOF") context of a pool without its
  lock, while `esdm_aux_init` in `esdm_reinit` releases and allocates it under
  the lock. A pass at that moment – the periodic worker, which `esdm_reinit`
  does not pause, or the #ac("RPC") self test – reported the auxiliary pool
  as failed (`ReinitRace`, `EsVerdictSound`); `esdm_aux_selftest` now reads
  under the lock (`EsLocked`).

#paragraph[Limits][Three configurations expect a violation in the current
code and state what the gate does not deliver. The verdict is read from an
atomic variable, so a failure recorded after the last check of a chunk or a
seed does not hold it back (`HandoutWindow`): what is handed out was produced
before the failure was recorded, but may be returned after it. The same holds
for an injection that passed its check (`InjectWindow`); the #ac("DRNG") it
seeds hands out nothing generated after the failure was recorded. A request that read the stop flag before
`esdm_fini` set it starts the periodic worker after `esdm_fini` joined the
threads (`StartAfterJoin`); that worker finds the request to leave before its
first wait and runs no pass (`LateWorkerIdle`), and it uses nothing
`esdm_fini` releases. Between the moment an implementation breaks and the
moment a self test records the failure, the gate holds nothing back; the
interval of the periodic self tests bounds that time.]

=== Auxiliary Pool <sec:fv-aux>

`tests/tla/EsdmAuxPool.tla` models `esdm/esdm_es_aux.c`: `ESDM_NUM_AUX_POOLS`
pools, each with its lock, its entropy count and the #ac("XDRBG") that
absorbs its data.

#paragraph[Model][Writers call `esdm_pool_insert_aux` with and without
entropy, `esdm_pool_add_entropy` (RNDADDTOENTCNT), `esdm_pool_set_entropy`
with zero (RNDCLEARPOOL), `esdm_aux_init` as the reinitialization and
`esdm_set_write_wakeup_bits`. Concurrent seedings of different #ac("DRNG",
pl: true) collect through `esdm_aux_get_backtrack`, as
`esdm_get_seed_buffers` does for each of them. An insert or extraction of the
#ac("XOF") may fail and discard the state; force_fips may switch the
#ac("SP") 800-90C oversampling at any time. Ghost counters record the credit
accepted, handed out and lost, with the reason of every loss. The need for
entropy, `esdm_need_entropy`, is evaluated with the steps of the code, none
of them under a lock: per pool the count and the oversampling are read, then
the threshold, then the pool size. Threads evaluate it on their own, and,
where a configuration says so, every operation publishes it afterwards as
the code does, through `esdm_shm_status_set_need_entropy` under the lock of
that function. A history variable records for every evaluation what held in
the states it ran across; it is computed from the state every step of any
thread leaves, not by the steps of the evaluation.]

#paragraph[Abstractions][Entropy is counted in units of 64 bits, the digest
size of a pool being 4 or 8 units and the oversampling one unit. The data is
left out: an insert carries at least the bits it is credited with. The
callers that start a seeding after an insert run after the pool lock is
released and are left out, as are `esdm_aux_fini` and allocation failures.
Of the status in shared memory, the need flag alone is modeled; its
semaphores and waiters are the subject of section @sec:fv-shm-status. Every
thread runs a bounded number of operations and then ends, so that the
deadlock check is on in every configuration and reports a thread that waits
for a lock forever; the configurations whose properties hold check in
addition that every thread ends (`AllDone`), under weak fairness.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`Conservation`], [The credit handed out plus the credit the pools hold
      never exceeds the credit accepted: no two extractions hand out the same
      credit, and no insert racing an extraction duplicates it.],
    [`Accounting`], [Every unit accepted is handed out, held, or lost to the
      capacity, a failing #ac("XOF"), clearing or the oversampling.],
    [`CountBound`], [The count of a pool never exceeds its digest size.],
    [`OneLock`], [A thread holds at most one pool lock, and none together
      with the lock of the published need; as, in addition, no other lock is
      taken under a pool lock, there is no lock order to keep.],
    [`ExtractLocked`, `UnlockOwned`], [An extraction drains the pool whose
      lock it holds and releases that lock.],
    [`CreditFitsOutput`], [An extraction credits no more bits than it
      outputs.],
    [`ClearHolds`], [A pool emptied as a whole – cleared, reinitialized, its
      state discarded – stays empty until it is credited again: no extraction
      running across it puts credit back.],
    [`ExtractSeeded`], [The #ac("XDRBG") an extraction took credit from is
      still instantiated when its output is generated.],
    [`CreditHasState`], [A pool holds credit only while its #ac("XDRBG")
      holds a state.],
    [`NeedSound`], [Full pools need no more entropy: an evaluation returns
      the need only if a pool was not full in some state it ran across, or
      force_fips switched meanwhile.],
    [`NeedNotSpurious`, `NeedNotMissed`], [An evaluation that returns the
      need ran across a state with the need, one that returns none across a
      state without, unless force_fips or the threshold changed meanwhile.
      Claimed for one pool only.],
    [`NeedSettles`], [Once every operation has completed, the published need
      is the need.],
    [`NeedFull`, `NeedThrFree`], [`NeedSound` without the exception for
      force_fips, `NeedNotSpurious` without the one for the threshold. Not
      claimed: they show that the exceptions are needed.],
    [`MaxAtExtract`], [The pool extracted from holds enough for the request,
      or the most of all pools.],
    [`NoLossWithRoom`], [An insert loses credit to the capacity of a pool only
      if no other pool has room for it.],
    [`AllDone`], [Every operation returns and every thread ends; with the
      deadlock check, no thread waits for a pool lock or the lock of the
      published need forever.],
  ),
  caption: [Properties of the auxiliary pool model],
) <tab:fv-aux-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Default`], [One pool, every writer, failing #ac("XOF"), two seedings], [holds], [81,203],
    [`Concurrent`], [Two pools], [holds], [89,728],
    [`Failures`], [Failing #ac("XOF") operations], [holds], [12,598],
    [`OsrOnce`], [The oversampling read once per extraction], [holds], [5,557],
    [`ThreshOnce`], [The threshold evaluated once per seeding], [holds], [9,582],
    [`RawRoom`], [The room of a pool measured by the raw count], [holds], [69],
    [`NeedReader`], [Two pools: an evaluation of the need next to inserts, a changed threshold, force_fips switching on], [holds], [2,873],
    [`NeedReaderWide`], [As `NeedReader`, with clearing, two thresholds, a seeding, force_fips switching twice (slow)], [holds], [381,805],
    [`NeedMoment`], [One pool: the value of an evaluation is the need of a state it ran across], [holds], [203,763],
    [`NeedMomentWide`], [As `NeedMoment`, with every writer, failing #ac("XOF"), two evaluations (slow)], [holds], [934,668],
    [`NeedSettles`], [Two pools, the need published after every operation, the setter of the threshold included, failing #ac("XOF")], [holds], [39,092],
    [`OsrRoom`], [Before the fix: pool selection under oversampling], [finds `NoLossWithRoom`], [32],
    [`RoomRace`], [Pool selection from unlocked counts (accepted by the code)], [finds `NoLossWithRoom`], [735],
    [`OsrFlip`], [Before the fix: oversampling switched off during an extraction], [finds `CreditFitsOutput`], [365],
    [`WakeupOsr`], [Before the fix: oversampling switched on after the threshold was set], [finds `NeedSound`], [398],
    [`MaxAtExtract`], [Lookup and extraction of the fullest pool (documented)], [finds `MaxAtExtract`], [2,931],
    [`ThreshPerIter`], [Before an earlier fix: the threshold per pool], [finds `UnlockOwned`], [500],
    [`AddUnseeded`], [Before the fix: a credit after a reinitialization], [finds `CreditHasState`], [149],
    [`NeedStaleFail`], [Before the fix: a failed insert publishes nothing], [finds `NeedSettles`], [81],
    [`NeedStaleWake`], [Before the fix: a changed threshold is not published], [finds `NeedSettles`], [47],
    [`NeedStaleFlip`], [As the code is: a switch of force_fips is not published], [finds `NeedSettles`], [117],
    [`NeedFlip`], [As the code is: force_fips switched off during an evaluation], [finds `NeedFull`], [493],
    [`NeedThreshold`], [As the code is: the threshold raised during an evaluation], [finds `NeedThrFree`], [28,222],
    [`NeedTornUp`], [As the code is: two pools read at different times, a need that never held], [finds `NeedNotSpurious`], [101,870],
    [`NeedTornDown`], [As the code is: two pools read at different times, a need missed], [finds `NeedNotMissed`], [80,765],
  ),
  caption: [Configurations of the auxiliary pool model and their results. For
    a configuration that finds a violation, the count is that of the states
    generated until then and varies by some states between runs with several
    workers.],
) <tab:fv-aux-results>

#paragraph[Results][Conservation, accounting, the bound of the count, the
lock discipline and progress hold for one and for two pools, with failing
#ac("XOF") operations, clearing and reinitialization racing two seedings
(configurations `Default`, `Concurrent`, `Failures`). The pool lock that
`esdm_pool_set_entropy` and `esdm_aux_init` take is needed: with the lock of
the clearing removed from the model, an extraction puts credit back into a
pool cleared meanwhile (`ClearHolds` violated in `Default` and `Concurrent`);
with that of the reinitialization removed, an extraction generates from a
context replaced under it (`ExtractSeeded` violated in both). The
configuration `ThreshPerIter` confirms the comment of
`esdm_aux_get_backtrack`: a threshold evaluated per pool, as before its fix,
breaks on one pool, extracts from another and releases a lock it does not
hold. The findings follow. The first three and the seventh are fixed, the
comment of the fourth is corrected, the fifth states what the code delivers,
and of the sixth two cases of three are fixed:]

- `esdm_pool_insert_aux` measured the room of a pool as the digest size less
  the count reduced by the oversampling, but the cap applies to the raw count.
  With more than one pool and the oversampling in effect, a pool holding up
  to 64 bits appeared empty and a full one appeared to have 64 bits of room:
  an insert of 512 bits went to a pool holding 64 bits and lost them while
  another pool was empty (`OsrRoom`, `NoLossWithRoom`). It now measures the
  room by the raw count (`RawRoom`). Under concurrency, the selection from
  unlocked counts still loses credit (`RoomRace`), which the comment of the
  function accepts.
- `esdm_aux_get_pool` read `esdm_compress_osr` once for the amount it takes
  and once for the discount. When force_fips was turned off in between, up to
  64 bits more were credited than the output holds (`OsrFlip`,
  `CreditFitsOutput`); it now reads the value once (`OsrOnce`).
- The write wakeup threshold was capped only when set. Turning force_fips on
  afterwards lowered what the pools hold below the threshold, and every
  evaluation of `esdm_need_entropy` returned the need with every pool full
  (`WakeupOsr`, `NeedSound`); it now caps the threshold when it reads it as
  well (`NeedReader`; with the cap removed from the model, `NeedReader`
  fails).
- Lookup and extraction are atomic only for a pool that satisfies the
  request, not for all pools, as the comment of `esdm_aux_get_backtrack`
  claimed. Otherwise the function locks the fullest pool again, and meanwhile
  another seeding may have drained it or an insert filled another pool
  (`MaxAtExtract`). The seeding is credited less than available, never more;
  the comment now states this.
- An evaluation of `esdm_need_entropy` is not a snapshot: it reads the counts,
  the threshold and force_fips one after the other, unlocked. What holds is
  `NeedSound`, and, for one pool, that the value is the need of a state the
  evaluation ran across unless force_fips or the threshold changed meanwhile
  (`NeedMoment`). Beyond that a single evaluation may be wrong in either
  direction: force_fips switched off between the sum of the pools and the
  pool size makes one evaluation return the need with every pool full
  (`NeedFlip`); a threshold raised after the count was read does the same
  with one pool (`NeedThreshold`); and with several pools the sum is of
  counts read at different times, so that the value may be a need that held
  in no state (`NeedTornUp`) or the absence of one that held in every state
  (`NeedTornDown`). The code accepts this by design: the need is a level that
  is evaluated again after every operation. For the published need the model
  shows that this suffices (`NeedSettles`): the evaluations that publish are
  serialized, each operation that changes a count or the threshold publishes
  after the change, and so the last evaluation runs across no change. Removing the
  publication after an extraction or the lock of the publication from the
  model violates `NeedSettles`. An evaluation outside that lock –
  `esdm_writer_wakeup` deciding whether to wake the writers blocked in the
  process, a status call – costs a writer one wakeup without need, or delays
  its wakeup to the next operation.
- `NeedSettles` holds only where every change is followed by a publication.
  Three changes were not: an insert whose #ac("XOF") operation failed
  discarded the credit of the pool and returned before publishing, leaving
  the published need off (`NeedStaleFail`); `esdm_pool_insert_aux` now
  publishes on that path as well (`NeedSettles`, with failing #ac("XOF")
  operations). `esdm_set_write_wakeup_bits` changed the threshold, one side
  of the need, without publishing it (`NeedStaleWake`); it now publishes the
  need after storing the threshold, the finding and fix that section
  @sec:fv-shm-status describes from the side of the status, and `NeedSettles`
  holds with the setter among the writers. `esdm_config_force_fips_set` still
  changes the need without publishing it (`NeedStaleFlip`): the published
  need is then stale until the next insert, credit, clearing, change of the
  threshold or seeding. This is left as it is, force_fips being switched at
  run time by the configuration interface of the library only.
- After `esdm_reinit` or a failed #ac("XOF") operation, the #ac("XDRBG") of a
  pool holds no state until the next insert. `esdm_pool_add_entropy`
  (RNDADDTOENTCNT) credited the first pool nevertheless (`AddUnseeded`,
  `CreditHasState`). `esdm_aux_get_pool` returns nothing for such a pool and
  leaves its count alone: no seeding obtained the credit, while the source
  reported it as available, which keeps the need off. The next insert, also
  one without entropy, initialized the pool and had the credit handed out for
  its data, although the data the credit was given for had been discarded.
  `esdm_pool_add_entropy`, and `esdm_pool_set_entropy` for a value above
  zero, now credit a pool only while its #ac("XDRBG") holds a state
  (`Default`, `Concurrent`).

None of the findings but the last credited more entropy than the pools
received; the last required a privileged caller of RNDADDTOENTCNT after a
reinitialization or a failed #ac("XOF") operation. The second, the third and
`NeedFlip` required force_fips to change at run time through
`esdm_config_force_fips_set`, and the first and the torn sums required more
than one pool (`num-aux-pools`). The model calls `esdm_pool_set_entropy` with
zero only, as every caller in the tree does.

=== Status in Shared Memory <sec:fv-shm-status>

`tests/tla/EsdmShmStatus.tla` models `esdm/esdm_shm_status.c` together with
its readers, the poll checkers of the #ac("CUSE") daemons
(`frontends/cuse/cuse_device.c`) and the aux client
(`frontends/aux-client/esdm_aux_need_entropy.c`).

#paragraph[Model][The server publishes the version, the operational state, the
need for entropy and the suspend generation in a System V segment under a
fixed `ftok` key, and wakes the readers through #ac("POSIX") named semaphores:
one per #ac("CUSE") daemon and a level-triggered one for entropy providers.
Segments and semaphores have identities: `IPC_RMID` takes a segment off the
key while attached processes keep it, `sem_unlink` takes a semaphore off its
name while its holders keep it. The concurrent processes are the thread
holding the lock of the initial #ac("DRNG"), which changes the operational
state and publishes it; threads that change the auxiliary pool and call
`esdm_shm_status_set_need_entropy`; the thread that changes the write wakeup
threshold; the `SIGUSR1` handler and the thread of the event interface, which
both raise the suspend generation; the server's start with the disposition of
`SIGUSR1` and the PID file, its exit with or without the #ac("IPC") cleanup,
and its restart; the start-up and the poll checker of one or of both
#ac("CUSE") daemons; aux clients. One step is one atomic variable access or
one system call: the poll checker reads the suspend generation, the version,
the operational state and the need for entropy in separate steps.]

#paragraph[Abstractions][All processes run under one user, so the ownership
checks are left out, as are the status text and the resize path. The poll
checker reads the status in every pass as if a poller were registered; the
registrations are the subject of section @sec:fv-cuse. The poller of a pass
is taken to wait since the end of the pass that woke its predecessor, which
is the earliest it can have registered. The signal handler is one step, which
is exact for the thread it interrupts and leaves out the steps of the other
threads meanwhile; the notification from the thread of the event interface
runs the same code step by step and covers them. An aux client makes a
bounded number of calls; where a configuration says so, a call may time out
at any time.]

#paragraph[Final state][Every environment process is bounded, and the model
names its one legitimate final state: the server is up, every budget is used,
every poll checker waits on its semaphore having seen the published status
and every suspend notification, and every aux client is done or waits while
no entropy is needed. A process that stutters in this state alone makes every
other state without successor a deadlock, so the deadlock check of TLC is on
in all configurations, and a wakeup lost for good is reported even where no
invariant is listed (`NoPostPublishHang`, `TwoAuxHang`). The liveness
properties assume weak fairness of every process.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`NoLostWakeup`], [A poll checker waits on its semaphore only after it
      has seen what its poll mask follows, or while a writer that stored a
      change has yet to post. Its parts are `NoLostVersion` (the ready
      version), `NoLostStatus` (operational state and need for entropy) and
      `NoLostSuspend` (the suspend notification owed to the poller).],
    [`NoOwedIdle`], [A writer that is idle owes no post: every store is
      followed by its posts.],
    [`OpFresh`, `NeedFresh`], [Once the threads that publish a state are idle,
      the segment shows the operational state and the need for entropy of the
      server.],
    [`StatusFresh`], [A segment that shows the ready version shows the state
      of the attached server once its threads are idle, whatever a
      predecessor left in the segment.],
    [`Connected`], [A running server and a running #ac("CUSE") daemon use the
      same segment and the same semaphore.],
    [`SemBinary`], [The semaphore of a #ac("CUSE") daemon toggles between 0
      and 1. The same statement for the level-triggered semaphore,
      `LevelSemBinary`, does not hold.],
    [`AuxNoLostWakeup`], [An aux client sleeps on the level-triggered
      semaphore only while no entropy is needed, or while a post is due.],
    [`AuxSpurious`], [An aux client is told to deliver entropy only if the
      segment showed the need during its call.],
    [`SuspendKills`], [A suspend signal sent to the process the PID file
      names does not end the server.],
    [Deadlock], [No state but the final state is without successor.],
    [`Settles`], [Liveness: the system reaches the final state and stays in
      it.],
    [`SuspendReaches`], [Liveness: a suspend notification reaches the poller
      of every #ac("CUSE") daemon.],
    [`AuxWoken`], [Liveness: while the need for entropy lasts, a waiting aux
      client returns.],
  ),
  caption: [Properties of the shared memory status model],
) <tab:fv-shm-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Writers`], [Two pool threads, the #ac("DRNG") thread and a suspend signal on a running server], [holds], [1,073,132],
    [`WritersWide`], [As `Writers`, two changes of the operational state (slow)], [holds], [2,699,830],
    [`WritersThread`], [As `Writers`, the suspend notification from a thread instead of the signal (slow)], [holds], [2,904,036],
    [`ThreadSuspend`], [The suspend notification from a thread, step by step, next to a pool thread and the #ac("DRNG") thread], [holds], [283,318],
    [`Thresh`], [Changes of the write wakeup threshold next to a pool thread and the #ac("DRNG") thread], [holds], [255,686],
    [`Restart`], [Restarts with `--keep_ipc` over a leftover segment, the #ac("CUSE") daemon starting before, between or after them], [holds], [184,227],
    [`SuspendRestart`], [Two suspend signals around a restart over a leftover segment], [holds], [74,771],
    [`TwoCuse`], [Both #ac("CUSE") daemons, the #ac("DRNG") thread and a suspend signal], [holds], [373,432],
    [`TwoCuseWriters`], [Both #ac("CUSE") daemons, a pool thread and a suspend signal], [holds], [423,300],
    [`TwoCuseRestart`], [Both #ac("CUSE") daemons over a restart with a leftover segment (slow)], [holds], [1,808,325],
    [`Aux`], [An aux client while the need for entropy changes twice], [holds], [18,540],
    [`Aux3`], [An aux client and three changes of the need, `Settles` and `AuxWoken`], [holds], [43,546],
    [`TwoAuxFix`], [Two aux clients passing the wakeup on while the need lasts], [holds], [283,980],
    [`AuxTimeout`], [Two aux clients whose calls may time out at any time], [holds], [452,466],
    [`ReinitLocked`], [The snapshot of the initialization under the lock of the initial #ac("DRNG")], [holds], [24,107],
    [`CuseEvictsFix`], [A #ac("CUSE") daemon starting with the server, removing no segment], [holds], [2,008],
    [`EarlySignalFix`], [A suspend signal ignored from before the PID file until its handler is installed], [holds], [5,610],
    [`Liveness`], [`Settles` over a restart with a pool thread and the #ac("DRNG") thread], [holds], [68,207],
    [`SuspendLiveness`], [`Settles` and `SuspendReaches` with a suspend signal around a restart], [holds], [27,443],
    [`TwoCuseLiveness`], [`Settles` and `SuspendReaches` with both #ac("CUSE") daemons and a suspend notification from a thread], [holds], [15,894],
    [`ThreadSuspendLiveness`], [`Settles` and `SuspendReaches` with a suspend notification from a thread and the #ac("DRNG") thread], [holds], [9,784],
    [`ThreshLiveness`], [`Settles` with changes of the threshold next to a pool thread], [holds], [9,970],
    [`TwoAuxLiveness`], [`Settles` and `AuxWoken` with two aux clients], [holds], [43,632],
    [`AuxTimeoutLiveness`], [`Settles` with an aux client whose calls may time out], [holds], [25,158],
    [`NeedRace`], [Before the fix: unserialized writers of the need for entropy], [finds `NeedFresh`], [5,825],
    [`SemDouble`], [Before the fix: concurrent posts], [finds `SemBinary`], [2,305],
    [`AuxSpurious`], [Before the fix: a post outliving the need], [finds `AuxSpurious`], [4,674],
    [`TwoAux`], [Before the fix: one post for two aux clients], [finds `AuxNoLostWakeup`], [10,155],
    [`TwoAuxHang`], [Before the fix, as `TwoAux`, no invariant listed], [finds a deadlock], [48,384],
    [`StaleVersion`], [Before the fix: the version published before the state], [finds `StatusFresh`], [184],
    [`NoPostPublish`], [Before the fix: no post after the version], [finds `NoLostVersion`], [1,161],
    [`NoPostPublishHang`], [Before the fix, as `NoPostPublish`, no invariant listed], [finds a deadlock], [1,161],
    [`Reinit`], [Before the fix: the snapshot of the initialization outside the lock], [finds `OpFresh`], [30,670],
    [`CuseEvicts`], [Before the fix: a #ac("CUSE") daemon removing the segment the server attaches], [finds `Connected`], [1,246],
    [`EarlySignal`], [Before the fix: a suspend signal before its handler], [finds `SuspendKills`], [16],
    [`TwoCuseTrigger`], [Before the fix: both #ac("CUSE") daemons on the one-shot suspend trigger], [finds `NoLostSuspend`], [5,134],
    [`TriggerRestart`], [Before the fix: a starting server clearing the one-shot suspend trigger], [finds `NoLostSuspend`], [6,614],
    [`ThreshNoPublish`], [Before the fix: a change of the threshold not published], [finds `NeedFresh`], [13],
    [`AuxLevelSem`], [The level-triggered semaphore with three changes of the need; harmless], [finds `LevelSemBinary`], [29,261],
    [`CleanupRace`], [Open: the cleanup at the exit without `--keep_ipc` and a starting #ac("CUSE") daemon], [finds `Connected`], [4,985],
  ),
  caption: [Configurations of the shared memory status model and their
    results; the deadlock check is on in all of them. Where a violation is
    found, TLC stops, and the state count varies between runs with several
    workers],
) <tab:fv-shm-results>

#paragraph[Sensitivity][Each safety property is violated by a configuration
that switches one fix off. Where the model has no switch, the guard was
removed in a scratch copy of the model and the suite run against it, once and
not as part of the suite. Without the refresh of the need for entropy in
`esdm_shm_status_init`, `Restart` and `CuseEvictsFix` find `StatusFresh`,
and so does `Restart` without that of the operational state. Without the posts after a store of the
operational state, `CuseEvictsFix` and `Thresh` find `NoOwedIdle` and
`Liveness` a deadlock; without the post of the second #ac("CUSE") semaphore,
`TwoCuse` finds `NoOwedIdle` and `TwoCuseLiveness` a deadlock. With the
generation the checker marks as seen taken at the end of its pass instead of
at the start, `SuspendRestart` and `ThreadSuspend` find `NoLostWakeup` and
`TwoCuseLiveness` a deadlock; with the generation reset by a starting server,
`SuspendRestart` finds `NoLostWakeup`. Without the notification at the exit,
`Restart` finds `NoLostWakeup`. With the PID file written before `SIGUSR1` is
ignored, `EarlySignalFix` finds `SuspendKills`. Without the post of the
level-triggered semaphore, `Aux` and `TwoAuxFix` find `NoOwedIdle`; without
the wakeup an aux client passes on, `TwoAuxFix` finds `AuxNoLostWakeup` and
`TwoAuxLiveness` a deadlock; with a re-check that ignores the flag, `Aux` and
`TwoAuxFix` find `AuxSpurious`. Two guards are not needed for any property
of this model: the post that re-synchronizes an existing semaphore at the
start (the post after the version reaches the same checker later; the
re-synchronization only shortens the time it shows the status of the
predecessor), and the withdrawal of the version at the exit, which serves the
`poll` of the #ac("CUSE") daemons (section @sec:fv-cuse).]

#paragraph[Findings][The wakeup protocol holds: a writer stores before it
reads the semaphore value, so a post it skips is one the checker has yet to
consume (`NoLostWakeup`, `Settles`), and a server restart with `--keep_ipc`
reconnects every reader (`Restart`). Model checking found eleven defects, ten
of them fixed since; the configurations `NeedRace`, `SemDouble`,
`AuxSpurious`, `TwoAux`, `StaleVersion`, `Reinit`, `CuseEvicts`,
`EarlySignal`, `NoPostPublish`, `TwoCuseTrigger`, `TriggerRestart` and
`ThreshNoPublish`, and `TwoAuxHang` and `NoPostPublishHang` with the deadlock
check, keep the code before the fixes:]

- `esdm_shm_status_set_need_entropy` loaded the published flag, evaluated the
  need and stored it without a lock, and its callers run concurrently: the
  older evaluation could be stored last and the segment could then report a
  need for entropy, or none, until the next call (`NeedRace`, `NeedFresh`). A
  lock now covers the three steps.
- The value test and `sem_post` were two steps, and a restarting server
  posted every existing semaphore: a semaphore rose above 1 (`SemDouble`,
  `SemBinary`). Posts are now combined: a caller that finds another one
  posting leaves its notification to that caller, which checks again after
  its post; the suspend signal handler takes part, as nothing blocks. A
  restarting server posts only a semaphore at 0 (`Writers`, `Restart`). This
  holds for the semaphores of the #ac("CUSE") daemons, which only the server
  posts. The level-triggered semaphore is also posted by an aux client that
  passes a wakeup on, with a value test and a post of its own, and reaches 2
  with three changes of the need (`AuxLevelSem`). This costs a wakeup and
  nothing else, as a woken client checks the flag (`Aux3`).
- The level-triggered semaphore kept its post when the need ended, and the
  next call of `esdm_aux_timedwait_for_need_entropy` returned 0 although no
  entropy was needed (`AuxSpurious`); with two aux clients, one post woke one
  of them (`TwoAux`, `AuxNoLostWakeup`). A woken client now returns only while
  the need lasts, passing the wakeup on to the next waiter, and continues
  to wait otherwise (`TwoAuxFix`, `TwoAuxLiveness`).
- `esdm_shm_status_init` published the ready version before it refreshed the
  operational state and the need for entropy: over the segment of an
  operational predecessor, a reader saw the #ac("ESDM") as operational
  although it was not (`StaleVersion`, `StatusFresh`). The version is now
  published last.
- With the version published last, every post of the initialization came
  before it. The version is part of what the poll mask of a #ac("CUSE")
  daemon follows: a poll checker that made its pass while the version was
  withdrawn and found it published when it went to wait blocked without
  having seen the status of the new server, with no post due
  (`NoPostPublish`, `NoLostVersion`). The window lies between the last post of
  the initialization and the store of the version, and needs a checker that
  runs in it. `esdm_shm_status_init` now posts the semaphores of the
  #ac("CUSE") daemons once more after the version (`Restart`, `Liveness`).
- `esdm_shm_status_init` took its snapshot of the operational state outside
  the lock of the initial #ac("DRNG"), so a newer state that a seeding thread
  published in between was overwritten permanently (`Reinit`, `OpFresh`); only
  `esdm_reinit` of the library reached it. The snapshot is now taken under the
  lock (`ReinitLocked`).
- A #ac("CUSE") daemon or aux client removed a segment without attachment as
  stale. Starting while the server attached, it removed the segment the
  server then used and created its own, which no process wrote (`CuseEvicts`,
  `Connected`). Readers now use a segment as found (`CuseEvictsFix`); a
  leftover of a crashed server is trusted until the server takes it over.
- A `SIGUSR1` between the creation of the PID file and the init ended a
  server without PID namespace (`EarlySignal`, `SuspendKills`). The server
  now ignores it before the PID file names it, until the handler is in place
  (`EarlySignalFix`).
- The suspend notification was a one-shot trigger in the segment, which the
  poll checker cleared after its pass. Both #ac("CUSE") daemons attach the
  same segment: the checker that ran first cleared the trigger, and the
  other one, woken by its own semaphore, found none and left its pollers
  asleep (`TwoCuseTrigger`, `NoLostSuspend`). A starting server cleared the
  trigger as well, and with it the notification of its predecessor's exit for
  a checker that had not run yet (`TriggerRestart`). With one daemon and no
  restart the trigger was sufficient. The segment now holds a generation
  counter that only the server writes, by counting up, and that a server
  taking a segment over keeps; each daemon compares it with the generation
  it has acted on, which it sets to the one loaded at the start of a pass
  (`TwoCuse`, `TwoCuseLiveness`, `SuspendRestart`). The layout of the segment
  changed with it, hence version 3.
- A change of the write wakeup threshold changes the need for entropy without
  a change of the auxiliary pool, and it was not published: the segment kept
  the old need until the pool changed the next time (`ThreshNoPublish`,
  `NeedFresh`). `esdm_set_write_wakeup_bits` now publishes it (`Thresh`,
  `ThreshLiveness`).
- Open: without `--keep_ipc`, the cleanup at the exit tests for attachments
  and removes in two steps; a #ac("CUSE") daemon starting meanwhile keeps a
  removed segment and an unlinked semaphore (`CleanupRace`). System V offers
  no removal conditional on attachments, so a fix needs readers that validate
  and reattach; the systemd units pass `--keep_ipc` and order the starts.
  Residual risk: a daemon affected by the race reads a status that is no
  longer updated, so its `poll` and its blocking reads follow a stale state
  until it is restarted; random numbers are not affected, as they come over
  the #ac("RPC") interface. The race requires a server started without
  `--keep_ipc` that exits while a #ac("CUSE") daemon starts.

=== CUSE Frontends <sec:fv-cuse>

`tests/tla/EsdmCuse.tla` models the #ac("CUSE") daemons behind `/dev/random`
and `/dev/urandom` (`frontends/cuse/cuse_device.c`, `cuse_random.c`,
`cuse_urandom.c`) together with the kernel side of #ac("FUSE") poll and
interrupts.

#paragraph[Model][Threads of user processes call `poll`, `read` with and
without `O_NONBLOCK` and a privileged #ac("IOCTL") on one open file. The
kernel puts a polling thread on the poll wait queue of the file and asks for
a notification only while a thread waits there; a thread whose `poll` found
another descriptor ready asks once and does not wait. A bounded pool of
#ac("FUSE") worker threads serves the requests, interrupts first;
`esdm_cuse_poll` replies, registers the poll handle and checks again under its
lock; `esdm_cuse_read_internal` asks the server under the reader side of the
privilege lock and waits for -EAGAIN to end; the poll checker notifies
registered handles after each post of the status semaphore, and every second
while no server publishes its status. The daemon reads the status segment
without a lock. The model therefore reads the version, the operational flag
or the state of the kernel device, the need for entropy, the suspend
generation of the segment and the generation the daemon has acted on in
separate steps, in `esdm_cuse_poll` as in the poll checker, whose pass,
marking of the suspend generation as acted on, look at the version and wait
on the semaphore are steps of their own. The server is the environment: it
changes its state and publishes it, counts the suspend generation up for a
suspend notification, exits, is killed and starts. Its exit and its start follow `esdm_rpc_server_fini`,
`esdm_shm_status_exit` and `esdm_shm_status_init` statement by statement, as
the daemon observes every intermediate state of the segment. The #acs("RNG")
of the kernel is ready from the start or becomes ready during the run.]

#paragraph[Abstractions][A call to the server under the reader lock is one
step, and after an #ac("RPC") error the read goes to the kernel device, where
it blocks until the #acs("RNG") of the kernel is ready. A store to the status
segment and the post following it are one step; the protocol of the posts is
the subject of section @sec:fv-shm-status. A lock operation shares its step
with the adjoining access where it commutes with the steps of the other
threads. All threads share one file, hence one registration. Time is left
out; the waits of `esdm_cuse_poll_wait` and of the poll checker are steps.
The model has one daemon and omits `O_SYNC`, `write` (it never waits), the
information #ac("IOCTL", pl: true), `release`, the shutdown and
`esdm_reinit`, which the server does not call.]

#paragraph[Fairness and termination][Every thread is weakly fair. Strong
fairness is assumed in one place only: where `esdm_cuse_poll` takes the poll
lock, which the poll checker takes and releases again and again while no
server publishes; with weak fairness there, `ServerDownFix`, `KernelLater`
and `StartRaceInFix` fail. The environment is not obliged to begin a change,
only to complete one it began, so every liveness property also covers the
runs in which the server stays as it is, in particular stays down. Deadlock
checking is enabled in every configuration. The model rests when every call
returned, apart from a `poll` whose event the status does not show while a
read would wait; a stuttering step is enabled in exactly these states, and
TLC reports every other state without a successor as a deadlock. Two
situations keep the model stepping and hide a hang from the deadlock check:
the pass of the poll checker every second while no server publishes, and a
read that waits by asking again. The liveness properties cover them.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`WaiterCovered`], [A thread asleep in `poll` is covered by a registered
      poll handle for its events, or by a poll request still under way.],
    [`PollReadable`], [`poll` reports `POLLIN` only if, at one of the reads of
      the status its answer comes from, a read would not have waited or the
      status showed the #ac("ESDM") operational.],
    [`NonblockNeverWaits`], [A read with `O_NONBLOCK` never waits.],
    [`UrandomFallback`], [`/dev/urandom` waits only while the #ac("ESDM") is
      operational and reads the kernel device otherwise.],
    [`PollNotStuck`, `InterruptNotStuck`], [No state without further steps
      leaves a poller asleep although the status shows its event or a read
      would not wait, or an interrupt unread while every worker waits in a
      read. The former names what the deadlock check reports.],
    [`PollWakes`, `PollLive`], [A poller wakes once the status shows its
      event, or a read would not wait, permanently.],
    [`SuspendWakes`], [A suspend notification the daemon has not acted on
      wakes the pollers registered meanwhile.],
    [`SuspendReaches`], [It wakes every thread asleep in `poll`, registered
      or not yet.],
    [`ReadsReturn`, `InterruptHonored`, `IoctlsReturn`, `ProbesReturn`], [A
      read returns once it would permanently not wait, an interrupted read in
      any case; a privileged #ac("IOCTL") and a `poll` that does not wait
      return.],
  ),
  caption: [Properties of the #ac("CUSE") frontend model],
) <tab:fv-cuse-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Poll`], [Pollers for `POLLIN` and `POLLOUT`, two workers, while the status changes], [holds], [2,407,603],
    [`PollWide` (slow)], [As `Poll`, with a second change of the need for entropy], [holds], [6,009,495],
    [`TwoPollers`], [Two pollers for `POLLIN`, two workers: one registration serves both], [holds], [119,516],
    [`PollLiveness`], [Pollers wake once their event holds permanently], [holds], [63,737],
    [`NullHandleFix`], [A poll without handle leaving the registration alone], [holds], [90,440],
    [`NonblockFix`], [A read with `O_NONBLOCK` returning -EAGAIN], [holds], [8,660],
    [`ExhaustFix`], [More workers than blocking reads: an interrupt is read], [holds], [7,465],
    [`Interrupt`], [A blocking read interrupted while a worker is free], [holds], [395],
    [`Reads`], [Reads and a privileged #ac("IOCTL") while the server exits, starts and turns operational], [holds], [103,108],
    [`ReadsKernelLater`], [The server gone before the kernel #acs("RNG") is ready: a blocking read returns once it is], [holds], [732],
    [`ServerDownFix`], [The server gone, for good or until a new one starts: poll follows the kernel device], [holds], [10,481],
    [`KernelLater`], [The server gone before the kernel #acs("RNG") is ready: the pass every second wakes the poller], [holds], [3,879],
    [`UrandomPollFix`], [`/dev/urandom` before the #ac("ESDM") is operational: poll follows the kernel device], [holds], [360],
    [`UrandomWaitFix`], [`/dev/urandom` reading the kernel device once the #ac("ESDM") stopped], [holds], [1,745],
    [`StartRaceFix`], [Exit and start, the post after the version: a poller for `POLLOUT` wakes], [holds], [11,413],
    [`StartRaceInFix`], [Exit and start of a server that is operational at once: a poller for `POLLIN` wakes], [holds], [26,206],
    [`KilledRestart`], [A killed server and its successor: a poller for `POLLOUT` wakes], [holds], [7,651],
    [`RestartPoll` (slow)], [Pollers for `POLLIN` and `POLLOUT` over an exit and a start in any state], [holds], [785,365],
    [`RestartTwice` (slow)], [Pollers for `POLLIN` and `POLLOUT` over two exits and starts], [holds], [6,218,589],
    [`SuspendPoll`], [Suspend notifications and a poller: each wakes it, no wakeup is lost], [holds], [12,030],
    [`SuspendPollWide` (slow)], [Suspend notifications, pollers for `POLLIN` and `POLLOUT`, status changes], [holds], [1,325,164],
    [`SuspendRaceFix`], [A suspend notification between the answer to a poll and its registration: the re-check notifies], [holds], [930],
    [`SuspendRestart`], [The suspend notification of an exit, kept over the start of a server], [holds], [24,542],
    [`NullHandle`], [Before the fix: a poll without handle replacing the registration], [finds `WaiterCovered`], [77,120],
    [`Nonblock`], [Before the fix: a non-blocking read waiting], [finds `NonblockNeverWaits`], [127],
    [`ServerDown`], [Before the fix: the server gone, poll waiting for it], [finds `PollNotStuck`], [1,372],
    [`UrandomPoll`], [Before the fix: `/dev/urandom` poll waiting for the #ac("ESDM")], [finds `PollNotStuck`], [127],
    [`UrandomWait`], [Before the fix: a waiting `/dev/urandom` read], [finds `UrandomFallback`], [455],
    [`StartRace`], [Before the fix: no post after the version, a poller for `POLLOUT` sleeping on], [finds `PollNotStuck`], [11,541],
    [`StartRaceIn`], [Before the fix: the same for `POLLIN`, found by the deadlock check], [finds a deadlock], [26,534],
    [`KilledRace`], [Before the fix: the same after a killed server], [finds `PollNotStuck`], [5,893],
    [`SuspendTrigger`], [Before the fix: the one-shot trigger of an exit, reset by the starting server], [finds `SuspendWakes`], [15,677],
    [`SuspendRace`], [Before the fix: a suspend notification between the answer to a poll and its registration], [finds `SuspendReaches`], [910],
    [`Exhaust`], [The remaining limit: as many blocking reads as workers, 1024 now], [finds `InterruptNotStuck`], [480],
    [`Killed`], [The remaining limit: a killed server, poll following its status], [finds `PollNotStuck`], [298],
    [`KernelNotReady`], [The remaining limit: no server, the kernel #acs("RNG") not ready, a non-blocking read waiting], [finds `NonblockNeverWaits`], [331],
    [`Suspend`], [By design: the suspend notification], [finds `PollReadable`], [176],
  ),
  caption: [Configurations of the #ac("CUSE") frontend model and their results. The
    default run leaves out those marked slow; a run that finds a violation stops
    there, so its state count varies with the order of the search],
) <tab:fv-cuse-results>

#paragraph[Findings][Poll registration and the poll checker lose no wakeup
of the status when every poll carries a handle, also while the server exits,
is killed and starts, and neither the poll lock nor the privilege lock
deadlocks (`Poll`, `PollLiveness`, `TwoPollers`, `StartRaceFix`,
`StartRaceInFix`, `KilledRestart`, `RestartPoll`, `Reads`); a suspend
notification wakes every thread asleep in `poll` (`SuspendPoll`,
`SuspendRaceFix`, `SuspendRestart`).
The following guards, each removed in a copy of the model, make a
configuration of the default run fail: the fallback mask (`ServerDownFix`),
the pass every second (`KernelLater`), the re-check after the registration,
the kept events and the notification of a replaced handle (`PollLiveness`),
the suspend generation captured at the start of a pass and its bit in the
mask (`SuspendPoll`), the post
of the exit (`ServerDownFix`), the writer preference of the privilege lock
(`Reads`). No configuration depends on the post with which a starting server
re-synchronizes the semaphore, given the post after the version, nor on the
kernel handing out interrupts before other requests. Model checking found
eight defects, two of them shared with the model of section
@sec:fv-shm-status, fixed since, one of them only bounded; the configurations
`NullHandle`, `Nonblock`, `ServerDown`, `UrandomPoll`,
`UrandomWait`, `StartRace`, `StartRaceIn`, `KilledRace`, `SuspendTrigger` and
`SuspendRace` keep the code before the fixes, and `Exhaust` shows the limit
that remains with as many readers as workers:]

- `esdm_cuse_poll` replaced the registration of the file also with a poll
  that carried no handle, which the kernel sends when no thread waited on the
  file at that moment. When the poll of a waiting thread registered between
  the reply and the registration of such a poll, its handle was destroyed and
  the thread slept through every change of the status (`NullHandle`,
  `WaiterCovered`). A poll without a handle is now only answered
  (`NullHandleFix`).
- `esdm_cuse_read_internal` ignored `O_NONBLOCK`: before the #ac("ESDM") was
  operational, a non-blocking read of `/dev/random` waited like a blocking
  one, whereas the kernel returns -EAGAIN (`Nonblock`, `NonblockNeverWaits`).
  It now returns -EAGAIN, or what it read so far (`NonblockFix`).
- A read waits in its #ac("FUSE") worker thread. libfuse ran at most 10
  workers, so 10 blocking reads before the #ac("ESDM") was operational
  occupied all of them: no worker read the interrupt of a signaled reader,
  which then could not be interrupted, and polls and
  #ac("IOCTL", pl: true) waited as well (`Exhaust`, `InterruptNotStuck`).
  With libfuse 3.12 or later the limit is now 1024 (`ExhaustFix`); as many
  blocking readers still occupy every worker. Residual risk: availability
  only – while the #ac("ESDM") is not operational, 1024 blocked readers of
  `/dev/random` (10 with an older libfuse) make the device unresponsive to
  signals, polls and #ac("IOCTL", pl: true) until it turns operational.
  Starting consumers after `esdm-wait-until-fully-seeded.service` (section
  @sec:usage-boot-gate) or reading with `O_NONBLOCK` avoids it; a fix needs
  reads that wait without holding a worker.
- `poll` derived readability from the published status alone, but a read
  falls back to the kernel device. After a server exit before the
  #ac("ESDM") was operational, and on `/dev/urandom` before it was, reads
  returned data while `poll` never reported `POLLIN` (`ServerDown`,
  `UrandomPoll`, `PollNotStuck`). The exit now withdraws the ready version;
  without it, and on `/dev/urandom` while the #ac("ESDM") is not
  operational, `poll` follows the kernel device, and the poll checker looks
  again every second, which is what wakes a poller when the #acs("RNG") of
  the kernel turns ready with no server running (`ServerDownFix`,
  `UrandomPollFix`, `KernelLater`).
- Once a `/dev/urandom` read switched to waiting for a reseed, it kept
  waiting when the #ac("ESDM") stopped being operational, whereas a new read
  would read the kernel device (`UrandomWait`, `UrandomFallback`). It now
  keeps its getter, whose answer then sends it to the kernel device
  (`UrandomWaitFix`).
- A starting server published the ready version last and posted nothing
  after it. A poll checker that took the last post of the start while the
  version was still withdrawn evaluated the kernel device instead of the
  status, as did an `esdm_cuse_poll` that re-checked in that window; the
  checker then found the version and waited on the semaphore with no post
  owed. A poller whose event the new server had
  published before the version slept until the next change of the status
  (`StartRace`, `KilledRace`, `PollNotStuck`; `StartRaceIn`, reported by the
  deadlock check). The window needs an exit and a start between two steps of
  the checker, or a predecessor that was killed and left the version in
  place. `esdm_shm_status_init` now posts after publishing the version
  (`StartRaceFix`, `StartRaceInFix`, `KilledRestart`, `RestartPoll`). This
  is the missing post after the version of section @sec:fv-shm-status, seen
  from the daemon.
- The suspend notification was a one-shot trigger in the status segment,
  which the poll checker cleared there and a starting server reset. A server
  that started before the poll checker had passed thereby took back the
  notification of its predecessor's exit, and a registered poller slept on
  (`SuspendTrigger`, `SuspendWakes`); section @sec:fv-shm-status has the
  second daemon that lost the trigger to the first. The notification is now a
  generation that only the server counts up and a starting server keeps,
  compared with the one the daemon acted on (`SuspendRestart`).
- A suspend notification did not reach a poll in flight, with the trigger as
  with the generation: when it arrived after `esdm_cuse_poll` had read the
  status for a poll, and the poll checker acted on it before that poll was
  registered, the checker found an empty list, and the re-check after the
  registration found nothing pending. The thread slept until the next change
  of the status (`SuspendRace`, `SuspendReaches`). The re-check now notifies
  also for a suspend generation newer than the one the poll was answered
  with (`SuspendRaceFix`, `SuspendPoll`).

Three limits remain, each kept by a configuration:

- A suspend notification reports `POLLIN` before the #ac("ESDM") is
  operational, by design (`Suspend`, `PollReadable`). The exit of the server
  is such a notification, and it stays pending until the poll checker acted
  on it; `PollReadable` is therefore not claimed where the server exits
  while the #acs("RNG") of the kernel is not ready, nor where a server starts
  after an exit.
- A server that is killed withdraws nothing: reads use the kernel device
  while `poll` keeps following the status the dead server left, until a new
  server starts (`Killed`, `PollNotStuck`; `KilledRestart`).
- The daemon reads the kernel device through a blocking descriptor. With no
  server running and the #acs("RNG") of the kernel not yet ready, a read of
  `/dev/random` waits there whatever its flags, so a read with `O_NONBLOCK`
  waits and a signal does not interrupt it (`KernelNotReady`,
  `NonblockNeverWaits`); it returns once the kernel is ready
  (`ReadsKernelLater`).

=== EGD Server <sec:fv-egd>

`tests/tla/EsdmEgd.tla` models the event loop of
`service-egd/server/esdm_egd_server.c`: one worker thread serves every client
of the regular and the #ac("PR") #ac("EGD") socket and must not wait for any
one of them.

#paragraph[Model][The worker runs `esdm_egd_handler`: it waits in
`epoll_wait`, accepts clients, reads and processes their commands in
`esdm_egd_read` and `esdm_egd_process`, closes or re-arms each connection with
`esdm_egd_conn_arm`, and ends each round with the retry walk over the
connections that hold a deferred blocking read, a parked non-blocking read or
a pending response. Clients connect to either socket, pipeline their
requests, read the responses, shut down their sending side and close at any
time; a client may stream write requests without end. The generators are the
environment: until it turns good, a non-blocking generation yields any amount
up to the request, nothing or an error, and a non-blocking read that got
nothing may find the #ac("ESDM") operational, which parks it, or not;
afterwards a generation yields all it is asked for.]

#paragraph[Abstractions][A request is a whole command of one of five classes:
answered from the state, non-blocking read, blocking read, write without
response and privileged command. A response goes out whole or stays pending.
Processing a command, with its generation and its first `send`, is one step.
epoll is level-triggered and returns at most `ESDM_EGD_MAX_EVENTS` of the
ready descriptors in any order; the poll timeouts and the park time are left
out, and the retry time of a failed `accept4` passes in an `epoll_wait` that
times out. The input buffer holds two commands in most configurations, one
in `BufOne`, `BufOneLive`, `HangupBufOne` and `RdhupCloses`, where a `recv`
leaves requests in the socket, and three in `HangupBehind`. The #ac("UID") of the peer is a field of the connection, latched at
`accept4`, and the properties compare what it permits with the real peer. The
model omits shutdown, the bulk insertion, unknown commands, commands split
across two `recv` calls and failures of `calloc`, `getsockopt` and
`epoll_ctl`.]

#paragraph[Waiting calls][The calls on which the worker could wait are the
`recv`, the `send` and the generation of a blocking read. In the model they
return as the code has them return: the sockets are created non-blocking
(`SOCK_NONBLOCK` at `socket` and `accept4`, `set_fd_nonblocking` for a socket
of systemd), and the worker generates with
`esdm_get_random_bytes_full_noblock`, `esdm_get_random_bytes_pr_noblock` and
`esdm_get_random_bytes`. That these calls return is read from the code and not
checked by this model; the locks taken inside them are the subject of the
models of sections @sec:fv-reseed and @sec:fv-aux. The constant `Block`
names the calls that wait instead. `WorkerNeverBlocks` therefore states that
the worker waits nowhere else, and each of the three calls, made to wait,
violates it (`BlockSend`, `BlockGen`, `BlockRecv`). With one `recv` per event
the worker never meets an empty socket: the model with a `recv` that waits
still satisfies the property (`RecvReady`), whereas the loop before the fix
ended in such a `recv` (`BlockRecv`).]

#paragraph[Deadlock and liveness][The deadlock check of TLC is enabled in
every configuration. The server does not end and the worker always has the
timeout of `epoll_wait` to go on with, so a deadlock is reached only when the
worker waits in a call and every client is done (`BlockDeadlock`). A hang short
of that is caught by `WorkerNeverBlocks`, which is checked in every
configuration of the server as it is, and by the liveness properties:
`Served` and `CleanedUp` under the assumption that the generators eventually
deliver, and `Reclaimed` without it. All of them hold under weak fairness of
the worker and of the clients. No fairness of `epoll_wait` among the ready
descriptors is assumed; the configurations with liveness properties have no
streaming client or return every ready descriptor.]

#figure(
  table(columns: (auto, 1.6fr, 1fr), align: left + horizon,
    table.header([Property], [Statement], [Result]),
    [`WorkerNeverBlocks`], [The worker has a step in every state: with
      `recv`, `send` and the generation of a blocking read returning instead
      of waiting, it waits nowhere.], [Holds; violated by each of the three
      calls when it waits],
    [`NoStarve`], [The worker takes no further input from one client while
      another descriptor is ready.], [Holds; violated before the fix],
    [`ArmedRight`], [At every `epoll_wait`, a connection is armed for
      `EPOLLOUT` while a response is pending, for nothing while a request is
      deferred or parked, and for `EPOLLIN` otherwise.], [Holds; violated
      by a deferred connection left armed],
    [`NoSpin`], [No event leaves its descriptor unchanged and still ready; a
      listener whose event accepted nobody, for a failed `accept4` or at the
      connection limit, is not ready at the next `epoll_wait` unless a
      connection was closed in between.],
      [Holds; violated before the fix for a listener whose `accept4` failed,
      and by a deferred connection left armed],
    [`DeferredState`], [A deferred request has collected less than it asked
      for, and no response or parked read stands beside it; a connection
      whose client is gone owes nothing.], [Holds],
    [`InOrder`, `FullAnswer`], [Each response reaches the client once, in the
      order of the requests; a blocking read is answered with all it asked
      for, however many rounds it is deferred.], [Holds],
    [`NoBypass`], [No command is carried out while an earlier one of its
      connection is deferred or parked.], [Holds],
    [`OneResponse`], [`esdm_egd_write` never finds a response in flight.],
      [Holds],
    [`NoLoss`], [The server closes a connection on its own only once the
      client has all its responses.], [Holds; violated when `EPOLLRDHUP`
      closes],
    [`NoDrop`], [When the server closes a connection for the end of its input
      or for a hang-up, every write and every privileged command the client
      sent has reached its handler. A connection closed for a failed
      generation or by the write timeout is exempt.], [Holds; violated before
      the fix of the hang-up],
    [`NoUseAfterFree`], [No connection is used after
      `esdm_egd_release_conn`.], [Holds],
    [`NoSigpipe`], [No `send` to a peer that is gone raises `SIGPIPE`.],
      [Holds; violated without `MSG_NOSIGNAL`],
    [`PrivOnlyRoot`], [A privileged command is carried out only for a peer
      with #ac("UID") 0, answered or not, and is refused with `-EPERM`
      otherwise.], [Holds],
    [`WithinCap`], [At most `ESDM_EGD_MAX_CONNECTIONS` connections are
      served.], [Holds; violated by one before the fix],
    [`Served`, `CleanedUp`], [Once the generators deliver, every request of a
      client that does not stream is answered and the connection of every
      client that is gone is released.], [Holds; before the fix not with a
      streaming client],
    [`Reclaimed`], [The connection of every client that is gone is released,
      whatever the generators do.], [Holds],
    [`ContentOK`], [Every response has the content the protocol states for
      its request.], [Holds],
  ),
  caption: [Properties of the #ac("EGD") server model],
) <tab:fv-egd-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Deferred`], [A deferred blocking read with a request behind it, a privileged command, half-close, close at any time; `Reclaimed`], [holds], [313,446],
    [`BufOne`], [The same with an input buffer of one command; `Reclaimed`], [holds], [265,087],
    [`RecvReady`], [The setting of `Deferred` with a `recv` that waits], [holds], [313,446],
    [`Park`], [A parked non-blocking read, the #ac("PR") socket, generation errors, the write timeout], [holds], [436,599],
    [`ParkLive`], [The same with `Reclaimed` (slow)], [holds], [436,599],
    [`Walk`], [Three clients, one event per round, hang-ups during the retry walk], [holds], [2,272,766],
    [`WalkLive`], [The same with `Reclaimed` (slow)], [holds], [2,272,766],
    [`Hangup`], [Writes and privileged commands of clients that close at once; `Reclaimed`], [holds], [146,744],
    [`HangupBufOne`], [The same with an input buffer of one command; `Reclaimed`], [holds], [126,312],
    [`HangupBehind`], [Clients that close with a write behind a deferred read and a privileged command behind an undelivered response; three responses for a socket that holds one], [holds], [1,091,332],
    [`Liveness`], [Requests answered, connections released], [holds], [105,056],
    [`LivenessPark`], [The same with parked reads], [holds], [138,450],
    [`BufOneLive`], [The same with an input buffer of one command and clients that half-close], [holds], [85,236],
    [`StarveFixed`], [A streaming client beside a waiting one], [holds], [3,824],
    [`AcceptFixed`], [A failing `accept4`], [holds], [5,368],
    [`CapFixed`], [Both listeners at the connection limit], [holds], [6,962],
    [`Starve`], [Before the fix: a streaming client], [finds `NoStarve`], [1,080],
    [`RdhupCloses`], [One `recv` per event, but `EPOLLRDHUP` still closes; an input buffer of one command], [finds `NoLoss`], [3,508],
    [`AcceptSpin`], [Before the fix: a failing `accept4`], [finds `NoSpin`], [209],
    [`Cap`], [Before the fix: both listeners in one batch], [finds `WithinCap`], [125],
    [`HangupBefore`], [Before the fix: `EPOLLHUP` closes at once], [finds `NoDrop`], [3,449],
    [`EpipeBefore`], [Before the fix: a `send` failing with `EPIPE` closes], [finds `NoDrop`], [706],
    [`KeepArmed`], [Mutation: a deferred connection left armed], [finds `NoSpin`], [404],
    [`KeepArmedState`], [The same mutation], [finds `ArmedRight`], [244],
    [`Sigpipe`], [Mutation: `send` without `MSG_NOSIGNAL`], [finds `NoSigpipe`], [209],
    [`BlockSend`], [Mutation: a `send` that waits], [finds `WorkerNeverBlocks`], [1,641],
    [`BlockGen`], [Mutation: a generation that waits], [finds `WorkerNeverBlocks`], [1,073],
    [`BlockRecv`], [Before the fix, with a `recv` that waits], [finds `WorkerNeverBlocks`], [2,757],
    [`BlockDeadlock`], [Mutation: a generation that waits and never delivers, clients that give up], [finds a deadlock], [198],
  ),
  caption: [Configurations of the #ac("EGD") server model and their results],
) <tab:fv-egd-results>

The state counts of the configurations that find a violation are those of one
run; TLC stops at the first violation, and with several workers the count
differs from run to run.

#paragraph[Findings][The deferral holds as designed: a blocking read that
cannot be served is completed exactly once, in order and in full, and a
deferred connection does not spin the worker – left armed for `EPOLLIN`, it
would (configuration `KeepArmed`). A peer may close between `epoll_wait` and
the `send` of its response regardless of the value of `ESDM_EGD_MAX_EVENTS`;
`MSG_NOSIGNAL` prevents this from raising `SIGPIPE` (`Sigpipe`).]

#paragraph[Input of a client that is gone][A write has no response, so a
client hands over its data by sending it and closing. The model records the
writes and privileged commands that reach their handler and compares them, at
the close of the connection, with those the client sent (`NoDrop`). The code
before `esdm_egd_hangup` closed a connection at `EPOLLHUP` and at a `send`
failing with `EPIPE` and discarded what was unread (`HangupBefore`,
`EpipeBefore`); the current code processes the input to its end, also when a
write waits in the input buffer behind a deferred read or a privileged command
behind an undelivered response (`HangupBehind`), and when the input takes
several events (`HangupBufOne`). The property does not cover two closes, which
give up the connection together with its unprocessed input: a generation that
fails with an error other than `-EAGAIN`, which closes the connection of a
blocking read, and the write timeout. The first also applies to a client that
is gone when the failure precedes the event that reports its hang-up.]

#paragraph[Defects][The handling of a hang-up predates the model:
`HangupBefore` and `EpipeBefore` reproduce the earlier revision and are not
counted below. Model checking found three defects, fixed since; the
configurations `Starve`, `AcceptSpin` and `Cap` keep the code
before the fixes, `RdhupCloses` one half of the first fix without the other:]

- `esdm_egd_read` received and processed in a loop until the socket was
  empty. A client sending faster than the worker processes kept the worker
  in this loop while the clients of both sockets waited (`Starve`,
  `NoStarve`); any local user could do this. It now receives once per event,
  and the level-triggered epoll returns to the client in the next round
  (`StarveFixed`). With one `recv` per event, requests may remain unread in
  the socket, and `EPOLLRDHUP`, which closed a connection before, would close
  one with such requests (`RdhupCloses`, `NoLoss`); only the end of the
  input now closes a connection (`BufOne`, `BufOneLive`).
- A failing `accept4` left the client queued and the listening socket armed
  and readable: `epoll_wait` returned at once, round after round, for as long
  as descriptors were in short supply (`AcceptSpin`, `NoSpin`). The listeners
  are now disarmed until a poll interval has passed or a connection is closed
  (`AcceptFixed`).
- `esdm_egd_handler` checked the connection limit once per round, but both
  listeners could arrive in one batch and each accept a client, one beyond
  the limit (`Cap`, `WithinCap`). The limit is now checked at each listener
  event (`CapFixed`).

=== Server Supervisor <sec:fv-supervisor>

`tests/tla/EsdmSupervisor.tla` models the #ac("PID") namespace supervisor of
`linux_isolate_namespace_prefork` (`common/linux_support.c`) with its two
callers, `esdm-server` and the #ac("CUSE") daemons, both started with
`--pid_namespace`.

#paragraph[Model][The supervisor and the daemon are processes with a signal
mask, a set of pending signals and a disposition per signal. A pending signal
that is not blocked is delivered before the next step of its process, also
out of the blocking `waitid` and `waitpid`, which `SA_RESTART` resumes; a
handler runs on top of the interrupted code, with the forwarded signals
blocked as the `sa_mask` of the forwarder states. The model follows the
kernel: `fork` passes the mask and the dispositions on, but no pending
signal; the daemon, init of the new namespace, receives from the supervisor
only the signals it blocks or has a handler for, and dies only by `SIGKILL`
or a fault; with `SIGCHLD` ignored the kernel reaps the daemon itself; a
reaped #ac("PID") may be handed out again; when the supervisor ends, the
daemon receives `SIGTERM` if its parent-death signal is set, which a `prctl`
sets and the privilege drop clears, and a supervisor that ended before the
`prctl` sends nothing. The daemon holds the read end of a pipe, the lifeline,
whose write end only the supervisor holds: a `poll` of it tells whether the
supervisor ended, whatever the user #ac("ID") of the daemon, and the daemon
that finds it ended sends `SIGTERM` to itself. The server polls after each
`prctl` and calls `prctl` again after its drop; a #ac("CUSE") daemon, which
changes its effective user #ac("ID") again for every privileged
#ac("IOCTL"), has a thread block in `poll` from before its drop on. Other
processes signal the supervisor at any time. The daemon exits with 0 after a
termination signal, or at any time with 1, by a fault or by `SIGKILL`.]

#paragraph[Abstractions][Four signals stand for the signals a handler can
catch: `SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM` are one, as both frontends
treat them alike; `SIGUSR1` is a second; the other signals of
`linux_term_signals`, which end a #ac("CUSE") daemon and which the server
does not handle, are a third; the remaining signals a process ends by
(`SIGABRT`, `SIGPIPE` and the fault signals, sent with `kill`), which no
daemon handles, are a fourth. `SIGKILL` sent to the supervisor also stands
for what else ends it and no handler prevents: the two real-time signals the
C library keeps for itself and a fault of its own. The daemon is reduced to
the steps that change its signal handling. The caller's signal mask is empty.
The model omits failures of `unshare` and `fork`, stop signals, the threads
of the daemon but the one at the lifeline, the privileged
#ac("IOCTL", pl: true) of a #ac("CUSE") daemon, which change nothing once
the drop cleared the parent-death signal, and signals sent to the daemon
directly.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`NoLostSignal`], [A termination signal sent to the supervisor once the
      fork began, or `SIGUSR1` sent once the daemon installed its suspend
      handler, is not taken by a handler of the supervisor, does not end the
      supervisor and is not discarded by the kernel at the daemon, unless the
      daemon ends first.],
    [`OwedInFlight`], [Such a signal is pending at the supervisor, held by a
      forwarder or pending at the daemon until the handler of the daemon
      ran: no forwarder returns without passing it on.],
    [`NoKillAfterReap`, `NoKillRecycled`], [No signal goes to the #ac("PID")
      of the daemon after the supervisor reaped it, nor to the process the
      #ac("PID") went to next.],
    [`ExitMirrors`], [A supervisor that ends by its own `exit` or `raise`
      ends with the exit status of the daemon, or by its signal.],
    [`CleanupOnce`], [`supervisor_exit` runs once, after the daemon ended, on
      every way out the supervisor takes itself.],
    [`NoUnforwardedKill`, `NoOrphan`], [No signal the daemon handles, and no
      other signal a handler can catch, ends the supervisor before it reaped
      the daemon. `SIGKILL` is not covered: `OrphanStops` is its property.],
    [`NoHang`], [Outside the final states the supervisor or the daemon can
      take a step, whatever the environment may still do. The final states
      are: both ended; the supervisor waits for a serving daemon; the
      supervisor ended and the daemon was never forked, or serves on with
      no parent-death signal set and no thread at the lifeline, which only
      the code before the fix reaches.],
    [`SupervisorExits`, `OwedReaches`, `StopEndsBoth`], [Liveness: the
      supervisor ends once the daemon did; a signal owed to the daemon
      reaches its handler or the daemon ends; a termination signal sent to
      the supervisor ends both.],
    [`OrphanStops`], [Liveness: a daemon that outlives its supervisor ends,
      at whichever step of the daemon the supervisor is killed.],
  ),
  caption: [Properties of the supervisor model],
) <tab:fv-supervisor-properties>

The liveness properties assume weak fairness of the supervisor and of the
daemon; the environment is not fair. Deadlock checking is on in every
configuration: the model ends in the final states named for `NoHang` by an
explicit step, so that any other state without a successor is reported. As
the environment can step in most states, the deadlock check alone would not
show a hang of the two processes; `NoHang` does. No configuration is slow.

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Server`], [The server, three signals: all safety and liveness properties but `OrphanStops`], [holds], [98,708],
    [`Liveness`], [The server, four signals: the same], [holds], [239,648],
    [`ChldIgnFixed`], [The server with `SIGCHLD` inherited as ignored: the same], [holds], [98,708],
    [`CuseFixed`], [The #ac("CUSE") daemon, three signals: its set, its handler before the fork, its latch; the same properties], [holds], [93,054],
    [`CuseLiveness`], [The #ac("CUSE") daemon, four signals: the same], [holds], [232,938],
    [`ServerKill`], [The server: `SIGKILL` to the supervisor at any step of the daemon; all properties], [holds], [47,461],
    [`CuseKill`], [The #ac("CUSE") daemon: the same], [holds], [49,753],
    [`ServerKillEarly`], [Before the fix: `SIGKILL` to the supervisor before the `prctl` of the daemon], [finds `OrphanStops`], [448],
    [`ServerKillDropped`], [Before the fix: `SIGKILL` to the supervisor of the serving server], [finds `OrphanStops`], [336],
    [`CuseKillDropped`], [Before the fix: `SIGKILL` to the supervisor of the serving #ac("CUSE") daemon], [finds `OrphanStops`], [306],
    [`ServerUsr1`], [`SIGUSR1` before the suspend handler (by design)], [finds `NoLostSignal`], [745],
    [`ServerSent`], [Before the fix: `SIGABRT` sent to the supervisor of the server], [finds `NoOrphan`], [61],
    [`CuseSent`], [Before the fix: `SIGABRT` sent to the supervisor of a #ac("CUSE") daemon], [finds `NoOrphan`], [66],
    [`ServerStray`], [Before the fix: a stray `SIGUSR2`], [finds `NoOrphan`], [66],
    [`ServerReap`], [Before the fix: a signal forwarded after the reap], [finds `NoKillAfterReap`], [525],
    [`ServerRecycled`], [Before the fix: the #ac("PID") handed out again], [finds `NoKillRecycled`], [767],
    [`ChldIgn`], [Before the fix: `SIGCHLD` inherited as ignored], [finds `CleanupOnce`], [2,226],
    [`CuseSet`], [Before the fix: a #ac("CUSE") signal outside the set], [finds `NoUnforwardedKill`], [70],
    [`CuseStartup`], [Before the fix: a stop before the #ac("CUSE") handler], [finds `NoLostSignal`], [614],
    [`CuseSession`], [Before the fix: the handler before the fork, no latch], [finds `NoLostSignal`], [901],
    [`CuseKillStartup`], [Before the fix: the parent-death signal before the #ac("CUSE") handler], [finds `OrphanStops`], [310],
    [`Unblocked`], [The code before the forwarded signals were blocked across the fork], [finds `NoLostSignal`], [75],
    [`ServerUsr1Unforwarded`], [Mutation: `SIGUSR1` left out of the forwarded set], [finds `NoLostSignal`], [287],
    [`ServerUsr1Dropped`], [Mutation: a forwarder that does not pass `SIGUSR1` on], [finds `OwedInFlight`], [1,061],
    [`ServerUsr1DroppedLiveness`], [The same mutation], [finds `OwedReaches`], [1,625],
  ),
  caption: [Configurations of the supervisor model and their results],
) <tab:fv-supervisor-results>

#paragraph[Findings][The supervisor meets every property for both daemons:
for the signals a handler can catch in the configurations `Server`,
`Liveness`, `ChldIgnFixed`, `CuseFixed` and `CuseLiveness`, and with a
supervisor killed at any step of the daemon in `ServerKill` and `CuseKill`.
Model checking and its review found six defects, fixed since; the
configurations named keep the code before the fixes to show that the
properties catch them:]

- The forwarders stayed installed after `waitpid` reaped the daemon: a signal
  arriving during `esdm_rpc_server_cleanup` or the re-raise went to the
  reaped #ac("PID"), possibly another process by then (`ServerReap`,
  `ServerRecycled`). The supervisor now waits with `WNOWAIT`, blocks the
  forwarded signals and clears the #ac("PID") before the reap. As a handler
  of the single-threaded supervisor runs to its end before the main code
  continues, either of the two suffices: the model passes with one of them
  removed and fails with both removed.
- With `SIGCHLD` inherited as ignored, `waitpid` failed: the supervisor exited
  with `EXIT_FAILURE`, without the cleanup (`ChldIgn`). It now resets
  `SIGCHLD` across the fork.
- The supervisor forwarded a fixed set: a termination signal of the
  #ac("CUSE") daemon outside it ended the supervisor and left the daemon
  unsupervised (`CuseSet`), as did a stray signal such as `SIGUSR2` sent to
  the supervisor of the server (`ServerStray`). Both supervisors now forward
  the signals of `linux_term_signals`; the server drops those it has no
  handler for as namespace init.
- The #ac("CUSE") daemon installed `esdm_cuse_install_sig_handler` after the
  fork and acted on a signal only once `esdm_cuse_session` existed: a stop
  during its start-up was lost (`CuseStartup`, `CuseSession`), and so was the
  parent-death signal (`CuseKillStartup`). It now installs the handler before
  the fork and records a signal until the session exists.
- The remaining signals a handler can catch and a process ends by, `SIGABRT`,
  `SIGPIPE` and the fault signals sent with `kill`, were not forwarded: one
  ended the supervisor and left the daemon unsupervised (`ServerSent`,
  `CuseSent`). The supervisor now forwards them as well, and the daemon drops
  them as namespace init; a fault the kernel raises for the supervisor itself
  keeps its default action.
- A supervisor that ended by `SIGKILL`, or by another cause no handler
  prevents, left a daemon that served on with no process to forward a signal
  to it. The parent-death signal stopped the daemon only if the supervisor
  ended between the `prctl` of the daemon and its privilege drop: before that
  `prctl` the kernel sends nothing (`ServerKillEarly`), and the change of the
  user #ac("ID") clears the setting, which no code set again
  (`ServerKillDropped`, `CuseKillDropped`). The daemon now holds the lifeline
  and polls it after the `prctl`; the server sets the parent-death signal
  again after its drop, in its main thread, as the setting ends with the
  thread that made it; a #ac("CUSE") daemon, in which every privileged
  #ac("IOCTL") clears the setting in all threads, has a thread wait at the
  lifeline instead. The daemon then shuts down as on a forwarded `SIGTERM`
  (`ServerKill`, `CuseKill`). In a copy of the model without the `poll`,
  `ServerKill` fails; `CuseKill` passes, as the thread at the lifeline
  also finds a supervisor that ended before the `prctl`.

One loss remains by design: a `SIGUSR1` before the server installs its
suspend handler is discarded (`ServerUsr1`); once the handler is installed,
the signal reaches it (`OwedInFlight`, `OwedReaches`). What a killed
supervisor can no longer do stays undone: the exit status of the daemon is
not mirrored and `supervisor_exit` does not run, so that the sockets, the
status segment, the semaphores and the #ac("PID") file of the server stay
behind, as they do after a server started without `--pid_namespace`, which
the daemon has no privileges to remove. A #ac("CUSE") daemon removes its
bind mount itself.

=== RPC Server <sec:fv-rpc-server>

`tests/tla/EsdmRpcServer.tla` models `service-rpc/server/esdm_rpc_server.c`
with the thread pool of `common/threading_support.c` that runs its threads.

#paragraph[Model][The main thread waits until the #ac("ES") monitor reports
the privileged initialization complete, opens the privileged socket, starts
the thread of the unprivileged interface and waits for its socket, drops its
privileges permanently and serves the privileged interface with one worker;
the unprivileged interface has one worker per online node. Each worker holds
the listening socket of its interface in an epoll set of its own,
level-triggered, keeps every connection it accepts and disarms the listener
at its connection cap. Clients connect with #ac("UID") 0 or another, send
requests – pipelined in some configurations, invalid ones in one –, match the
responses by order, close at any time and, in some configurations, connect
again. A termination signal arrives at any time; opening the unprivileged
socket, the privilege drop, `eventfd` and `thread_start` may fail, `accept4`
may fail for want of descriptors, an accepted connection may be released for
want of memory, and the set-up of a worker's epoll set, `epoll_wait` and the
registration of an accepted connection may fail. The shutdown runs
`esdm_rpc_server_fini`, which joins the workers, and `esdm_fini`, which joins
every thread of the pool once more.]

#paragraph[Abstractions][A request is one message. A valid one is served in
two steps: the handler up to its authorization, and its effect with the
reply. Every handler replies exactly once and none blocks – the random bytes
handlers call `esdm_get_random_bytes_full_noblock`,
`esdm_get_random_bytes_pr_noblock` and `esdm_get_random_bytes`, which return
`-EAGAIN` instead of waiting. Every handler of the privileged interface asks
`esdm_rpc_client_is_privileged` first; the model keeps the answer in a
variable of the worker and records the calls that took effect. A write
delivers, fails because the client closed, or times out while the client
leaves responses unread. The idle timer fires at any time in some
configurations and never in others, in which a worker blocked in `epoll_wait`
learns of a shutdown from its eventfd only. Each worker has a slot of the
thread pool to itself. A switch per fix selects the code before or after it;
two further switches seed a defect the code never had – a handler that closes
the connection instead of replying, and a privileged handler without the
authorization –, which shows the properties on replies and on the
authorization able to fail. The model omits the #ac("EGD") server, socket
activation, a failing `epoll_ctl` that re-arms the listener, and the turn the
prediction resistance call reserves for privileged clients.]

#paragraph[Termination and idling][Deadlock checking is on in every
configuration. The model ends explicitly: once `main` returned, a `connect`
fails, a pool thread that was never used ends, and the source of the signal
ends last, so that the final state is the one in which every process ended.
A server that is not shut down idles; the source of the signal stutters in
exactly the states in which both interfaces serve, every client is done and
no connection is open or queued. Every other state without a step is
reported: a client that waits for an answer or in the backlog, a start-up or
a shutdown that does not go on.]

#paragraph[Unanswered requests][The server closes a connection with a
request unanswered in these cases only, and `RepliedOrBroken` with
`ClosedForCause` fail on any other: the request is invalid (too short, too
long, an unknown method, not unpackable), which closes the connection without
a reply; the reply cannot be delivered, because the client closed or left
responses unread until the write timed out; the client hung up; the idle
timer closes a connection that was not read for an interval while a request
arrives; `accept4` succeeded, but memory or the epoll set had no room for the
connection; the server shuts down. The case of the idle timer is a property
of the code: a request that arrives while the timer pass runs is dropped
with its connection, and the client has to send it again on a new one.]

#figure(
  table(columns: (auto, 1.6fr, 1fr), align: left + horizon,
    table.header([Property], [Statement], [Result]),
    [`ConnOwned`, `CountsConsistent`], [A connection is open exactly while
      the epoll set and the list of one worker hold it; the connection count
      of a worker equals its list and stays within the cap.], [Holds],
    [`ExactlyOnce`], [The responses written on a connection are as many as
      its requests answered, and each of these was sent. The model serves one
      request per worker at a time and its handlers reply once: the property
      checks the consistency of the model, not the handlers.], [Holds],
    [`RepliedOrBroken`], [A request that a worker read is answered, unless it
      is invalid or its reply could not be delivered.], [Holds; violated by
      the seeded defect (`NoReply`)],
    [`AnsweredOrClosed`], [The connection of an invalid request, or of a
      reply that could not be delivered, is closed.], [Holds; violated before
      the second fix (`LostReply`)],
    [`ClosedForCause`], [A connection is closed with a request unread only
      when the client closed it, an earlier request was invalid or its reply
      lost, the idle timer closed it, it was released at accept, or the
      server shuts down.], [Holds],
    [`InStep`], [A client that matches responses by order receives the
      answer to its request.], [Holds; violated before the second fix
      (`OutOfStep`)],
    [`NoUseAfterFree`], [No worker uses a freed connection, the freed thread
      array of `esdm_rpcs_workerloop` or the `struct esdm_rpcs` of a function
      that returned.], [Holds; violated before the first fix (`EfdFail`)],
    [`PromptShutdown`], [Once the exit flag is set, a worker blocked in
      `epoll_wait` has its eventfd written, or the thread that started it is
      yet to write it.], [Holds; violated before the first fix (`EfdHang`)],
    [`NoCircularWait`], [The join of `esdm_fini` never waits for the thread
      of the unprivileged interface while that thread waits for a worker slot
      the join holds.], [Holds; violated before the third fix
      (`JoinDeadlock`)],
    [`NoAcceptSpin`], [A worker is not woken twice in a row for a backlog it
      does not accept from: after an `accept4` that failed for want of
      descriptors until its retry is due or one of its connections closed,
      and at its connection cap.], [Holds; violated before the fourth fix
      (`AcceptSpin`) and with the listener armed at the cap (`CapSpin`)],
    [`WorkersServe`], [A worker that left on a failure has ended the
      server.], [Holds; violated before the fifth fix (`WorkerExit`)],
    [`PrivAuthorized`], [A privileged call takes effect only on the
      privileged interface and for a client that had #ac("UID") 0 when it
      connected, also on a privileged socket open to all.], [Holds; violated
      by the seeded defect (`PrivNoCheck`)],
    [`PrivAtCall`], [... with #ac("UID") 0 at the time of the call.],
      [Violated, documented (`PrivDrop`)],
    [`ServeAfterDrop`, `DropAfterPrivInit`], [No request is served before the
      permanent privilege drop, and the drop follows the privileged
      initialization.], [Holds],
    [`NoServeAfterFini`, `NoConnLeak`], [No request is served after
      `esdm_fini`; a worker that ends leaves no connection open.], [Holds],
    [Deadlock], [Every state without a step is the final one or an idle
      one.], [Holds; violated before the fifth fix (`WorkerExitHang`)],
    [`ShutdownTerminates`, `WorkersTerminate`], [A shutdown ends `main` and
      every worker job.], [Holds],
    [`FailureEnds`, `WorkerFailureEnds`], [A failure of the unprivileged
      interface, and a worker that left on a failure, end `main`.], [Holds],
    [`RequestsAnswered`], [Every request is answered, or its connection is
      closed or refused – for the causes of `RepliedOrBroken` and
      `ClosedForCause` only.], [Holds],
    [`CleanedUp`, `AcceptedOrRefused`], [A connection the client closed is
      freed; a queued connection is accepted or reset.], [Holds],
  ),
  caption: [Properties of the #ac("RPC") server model],
) <tab:fv-rpc-server-properties>

The liveness properties assume weak fairness of every thread and client.
They are not checked where `accept4` may fail: nothing bounds the time for
which the descriptors stay exhausted, and a queued client waits as long.

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Accept`], [Accept races of two workers, hang-up, EOF], [holds], [1,405,640],
    [`AcceptRetry`], [A failing `accept4` retried after an interval or a closed connection; a connection released at accept], [holds], [301,940],
    [`Priv`], [Privileged calls of clients with and without #ac("UID") 0], [holds], [1,103,860],
    [`PrivTwoConn`], [A root and a non-root connection on the privileged worker], [holds], [213,236],
    [`EfdFix`], [Every eventfd created before the first worker, a failing start ending the server], [holds], [673,383],
    [`EfdEnds`], [A failing eventfd or start ends the server, no client], [holds, L], [25,937],
    [`Cap`], [The connection cap, the listener disarmed], [holds, L], [107,876],
    [`Idle`], [Two workers, a client closing at any time, idle reaping], [holds], [889,664],
    [`IdleLive`], [One worker, a client closing at any time, idle reaping], [holds, L], [70,196],
    [`Liveness`], [Two workers, a client closing at any time, idle reaping], [holds, L, slow], [889,664],
    [`LostReplyFix`], [A lost reply closing the connection], [holds, L], [20,060],
    [`BadReq`], [Invalid requests closing the connection, the client connecting again], [holds, L], [153,764],
    [`TwoConn`], [Two connections on one worker], [holds, L], [135,228],
    [`TwoConnClose`], [Two connections on one worker, closing at any time], [holds], [1,374,180],
    [`TwoConnIdle`], [Two connections on one worker, idle timer, pipelining], [holds, slow], [49,696,012],
    [`Reconnect`], [A client that closes and connects again], [holds, L], [137,636],
    [`ReconnectIdle`], [A reconnecting client with the idle timer], [holds], [990,228],
    [`ReconnectCap`], [Two reconnecting clients at the connection cap], [holds], [257,220],
    [`WorkerExitFix`], [A worker leaving on an epoll failure ends the server], [holds, L], [185,924],
    [`WorkerExitPriv`], [The privileged worker leaving on an epoll failure], [holds, L], [194,745],
    [`WorkerExitTwo`], [One of two workers leaving on an epoll failure], [holds, L, slow], [2,334,792],
    [`JoinFix`], [The shutdown waiting for the unprivileged interface thread], [holds, L], [19,770],
    [`Startup`], [Start-up with failures and a termination signal], [holds, L], [66,847],
    [`Shutdown`], [The shutdown from every state of the start-up and the service], [holds, slow], [10,659,788],
    [`Terminate`], [The shutdown ends `main` and every worker], [holds, L, slow], [659,840],
    [`EfdFail`], [Before the fix: an eventfd failing after the first worker started], [finds `NoUseAfterFree`], [3,251],
    [`EfdHang`], [Before the fix: a worker learning of the shutdown late], [finds `PromptShutdown`], [1,463],
    [`LostReply`], [Before the fix: a response dropped, the connection kept], [finds `AnsweredOrClosed`], [6,167],
    [`OutOfStep`], [Before the fix: a pipelining client after a dropped response], [finds `InStep`], [10,450],
    [`JoinDeadlock`], [Before the fix: a termination signal while the unprivileged workers start], [finds `NoCircularWait`], [4,985],
    [`AcceptSpin`], [Before the fix: `accept4` failing for want of descriptors], [finds `NoAcceptSpin`], [3,081],
    [`CapSpin`], [The listener left armed at the connection cap], [finds `NoAcceptSpin`], [16,549],
    [`WorkerExit`], [Before the fix: a worker leaving on an epoll failure], [finds `WorkersServe`], [754],
    [`WorkerExitHang`], [Before the fix: a client queued at an interface without workers], [finds a deadlock], [11,145],
    [`NoReply`], [Seeded defect: a handler closing instead of replying], [finds `RepliedOrBroken`], [2,965],
    [`PrivNoCheck`], [Seeded defect: a privileged handler without the authorization], [finds `PrivAuthorized`], [2,868],
    [`PrivDrop`], [A client dropping its privileges after connecting (documented)], [finds `PrivAtCall`], [5,191],
  ),
  caption: [Configurations of the #ac("RPC") server model and their results.
    All run with deadlock checking; "L" marks the ones that check liveness
    properties, "slow" the ones left out of the default run],
) <tab:fv-rpc-server-results>

#paragraph[Findings][Model checking found four defects and the review of the
model a fifth, all fixed since, confirms a documented limitation and states
one behavior left open, the idle timer above. The
configurations named first show each defect in the code before its fix; the
ones named last check the code after it:]

- When `eventfd` failed for a worker after the first,
  `esdm_rpcs_workerloop` freed the array holding the arguments of the
  workers already started and returned, and `esdm_rpcs_unpriv_init` returned
  with the `struct esdm_rpcs` of the interface on its stack. The running
  workers read their arguments from the freed array and dereferenced the
  returned frame with every request (`EfdFail`, `NoUseAfterFree`); nothing
  wrote their eventfds, so a shutdown waited for their idle timers
  (`EfdHang`, `PromptShutdown`); and the start-up, past the unprivileged
  initialization already, did not learn of the failure. The privileged
  interface, with its single worker, was not affected.
  `esdm_rpcs_workerloop` now creates every eventfd before the first worker
  starts; a failed `thread_start` ends the server once the workers already
  started are joined, and a failure of the unprivileged interface while
  serving ends the server with its error (`EfdFix`).
- `esdm_rpcs_write_data` marked a connection broken only when `write` failed
  with `EPIPE`, and reported a timed out wait for room in the socket as the
  `EAGAIN` of the failed write. When a client left responses unread, a
  response was dropped and the connection stayed open: a client that
  pipelines its requests and matches responses by order took the next answer
  for the dropped one (`LostReply`, `OutOfStep`). Every reply that is not
  delivered now marks the connection broken, which closes it, and a timeout
  is reported as `-ETIMEDOUT` (`LostReplyFix`). The #ac("ESDM") client sends
  one request at a time and resets the connection when it abandons an
  answer; it was not affected.
- `esdm_fini` joins every thread of the pool through
  `esdm_es_mgr_finalize`, the thread of the unprivileged interface among
  them, and holds the worker slots flagged for shutdown meanwhile. A
  termination signal during the start of the unprivileged workers left that
  thread waiting for a flagged slot while the join waited for the thread: the
  shutdown hung (`JoinDeadlock`, `NoCircularWait`). `esdm_rpc_server_fini`
  now waits for the thread of the unprivileged interface before the first
  join (`JoinFix`, `Startup`, `Terminate`).
- An `accept4` that failed for want of descriptors or memory left the
  level-triggered listener armed and readable, and the worker accepted again
  at once in a busy loop (`AcceptSpin`, `NoAcceptSpin`); a local client that
  holds connections up to the descriptor limit could cause it. The worker
  now disarms the listener for 250 milliseconds, or until one of its
  connections closes (`AcceptRetry`). The listener is disarmed at the
  connection cap for the same reason (`CapSpin`, `Cap`).
- A worker left its loop when `epoll_wait` failed, when the registration of
  an accepted connection failed with an error other than `ENOMEM` and
  `ENOSPC`, or when the set-up of its epoll set or timer failed, and nothing
  ended the server: the interface kept listening with fewer workers, the
  privileged one, which has a single worker, with none, and its clients
  waited in the backlog (`WorkerExit`, `WorkersServe`; `WorkerExitHang`,
  deadlock). The model had no such exit before the review. The worker now
  signals the exit and returns its error, which ends the server as a worker
  that fails to start does (`WorkerExitFix`, `WorkerExitPriv`,
  `WorkerExitTwo`).
- A privileged call is authorized by the #ac("UID") the client had when it
  connected (`SO_PEERCRED`): a client that drops its privileges keeps a
  privileged connection (`PrivDrop`, `PrivAtCall`), as `esdm_rpc_server.h`
  documents for the #ac("CUSE") daemons.

=== RPC Client <sec:fv-rpc-client>

`tests/tla/EsdmRpcClient.tla` models the #ac("RPC") client library of
`service-rpc/client/`: the connection pool, `esdm_client_invoke` with its
connect, write and read paths, and the calls for random bytes.

#paragraph[Model][Client threads call `esdm_rpcc_get_random_bytes`,
`esdm_rpcc_get_random_bytes_full`, `esdm_rpcc_get_random_bytes_full_noblock`
and `esdm_rpcc_get_random_bytes_full_timeout`, and
`esdm_rpcc_rnd_add_entropy` stands for the requests that must not run twice;
`esdm_rpcc_get_random_bytes_pr` and `esdm_rpcc_get_random_bytes_pr_noblock`
share the client logic of the first two. A thread checks a connection out
through its `ref_cnt` – one trylock pass over the pool, then a wait for its
home node outside the connection lock, counted in `waiters` – and holds the
connection's `lock` across one request. The socket of a connection consists
of the requests the server has not answered, the responses the client has
not read and a pending `ECONNRESET`; closing the client end discards it, so
that a late answer reaches a dead socket. Per connection, the server answers
with data or `-EAGAIN`, loses an answer, closes with or without a request
unread, restarts and refuses connects. The environment raises the interrupt
function of a call, sticky or one-shot, and the deadline of
`esdm_rpcc_get_random_bytes_full_timeout`; a thread may be canceled in
`read()`, another caller may keep the only connection past any deadline, and
`esdm_rpcc_fini_unpriv_service` may tear the pool down while threads use it
and wait for it. The threads make a bounded number of calls and end, and the
server and the environment end with them, so that every other state without a
successor is a hang, which the deadlock check of every configuration reports;
in the configurations named so, the threads call without end.]

#paragraph[Abstractions][Time is left out: a `read()` that finds nothing is
one receive timeout, and the bound of an invoke may pass at every re-send.
The connect loop is one step, and the size negotiation and the fork handlers
are omitted.]

#paragraph[Assumptions][A request carries a ghost tag naming its thread and
its write, which the server echoes. The code has no counterpart:
`esdm_rpc_client_pack` sends the request identifier 0, and
`esdm_rpc_client_read_handler` compares neither the request identifier nor
the method index that the server echoes, so that the client takes the next
message of a socket for the answer. `ResponseMatch` is therefore a statement
about the client under the assumption that the server writes at most one
response per request it read, in the order of the requests. The server of
the model does so, as `esdm_rpcs_unpack` does; the model assumes this and
does not show it, and the configuration `ExtraAnswer` drops the assumption.
Every step is weakly fair. The wait for the `ref_cnt` mutex of a busy
connection is strongly fair, that is, a waiting thread obtains the mutex
although other threads keep taking it in between; POSIX does not guarantee
this of `pthread_mutex_lock`, and the configuration `Starve` drops it.]

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`ResponseMatch`], [Given a server that writes at most one response per
      request, a call takes the response to its own request or none: never
      that of another thread and never the late answer of a request
      abandoned after a receive timeout, an interrupt, a closed connection
      or a canceled owner.],
    [`ExclusiveUse`], [A socket is used by one thread at a time, the one that
      checked the connection out and holds its lock.],
    [`NoUseAfterClose`, `NoLockLeak`], [`read()` and `write()` act on open
      sockets only; between calls a thread holds no connection and no lock.],
    [`NoUseAfterFini`], [No connection is used or waited for once
      `esdm_rpcc_release_conns` tore it down, and no getter reads the pool
      once it is freed.],
    [`BlockingNoEagain`, `NoblockNoWait`], [The calls that wait for seeding
      never return `-EAGAIN`; only they wait between requests.],
    [`SentOnce`, `RanOnce`], [A request that is not re-sendable is written,
      and run by the server, once per call, repetitions by `esdm_invoke`
      included.],
    [`DeadlineNoWait`], [A call of `esdm_rpcc_get_random_bytes_full_timeout`
      past its deadline is never left waiting for a connection that another
      caller keeps.],
    [`GoodCallsSucceed`], [A call made once the server answers permanently
      succeeds, regardless of the sockets that earlier lost answers, closes
      and restarts left behind.],
    [`CallsReturn`], [Once the server answers permanently, every call
      returns. With threads that call without end this is freedom from
      starvation, and it holds only under the assumed strong fairness of the
      wait for `ref_cnt`.],
    [`CallsProgress`], [Whatever the server does, a call returns or keeps
      asking: it is never left waiting permanently for a lock, a connection or
      an answer. Only the calls that wait for seeding ask without end, while
      the server answers `-EAGAIN`.],
    [`DeadlineReturns`], [A call of
      `esdm_rpcc_get_random_bytes_full_timeout` returns once its deadline has
      passed, whatever the server does and however long other callers keep
      the connections.],
    [Deadlock], [No state other than the final one, in which all calls have
      returned, lacks a successor. Checked in every configuration.],
  ),
  caption: [Properties of the #ac("RPC") client model],
) <tab:fv-rpc-client-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Shared`], [Two threads on one connection, lost answers, closes, a restart, sticky interrupts], [holds], [2,320,845],
    [`Endless`], [Any number of calls per thread on one connection, lost answers, closes, a restart], [holds], [1,155,176],
    [`PoolQuick`], [Two threads, two connections, requests of one and two chunks, closes], [holds], [2,345,628],
    [`Pool3`], [Three threads, two connections: the wait for the home connection], [holds], [1,308,102],
    [`Pool` (slow)], [Two threads, two connections, polling calls, closes, a restart], [holds], [7,005,733],
    [`Interrupt` (slow)], [One-shot interrupts, the deadline of the timeout call], [holds], [5,282,870],
    [`Deaths`], [A thread canceled in `read()`, `EOWNERDEAD`], [holds], [491,762],
    [`Fini`], [Teardown while the connection is used and waited for], [holds], [104,225],
    [`OnceFixed`], [An interrupt after the write reported as unknown outcome], [holds], [1,464,622],
    [`OnceSticky`], [A sticky interrupt with `esdm_invoke`], [holds], [536,310],
    [`ReadErrFixed`], [The socket reset on every failed read], [holds], [579,954],
    [`HogFixed`], [A caller keeping the only connection, the deadline bounding the wait; `DeadlineReturns`], [holds], [341],
    [`Deadline` (slow)], [`DeadlineReturns` while the server answers `-EAGAIN`, loses answers and closes], [holds], [242,584],
    [`LiveChunks`], [`CallsReturn`, `CallsProgress`: requests of two chunks that poll, one connection], [holds], [30,794],
    [`LivePool`], [`CallsReturn`, `CallsProgress`: two connections, requests of two chunks], [holds], [69,335],
    [`LivePool3` (slow)], [`CallsReturn`, `CallsProgress`: three threads, two connections], [holds], [1,308,102],
    [`Progress`], [`CallsProgress` with a server that loses answers, closes and never recovers], [holds], [58,935],
    [`Fair`], [`CallsReturn`, `CallsProgress`: two threads calling without end, strongly fair `ref_cnt`], [holds], [58,984],
    [`Liveness` (slow)], [`CallsReturn` after lost answers, closes and a restart], [holds], [308,785],
    [`Starve`], [Assumption dropped: `ref_cnt` only weakly fair, threads calling without end], [finds `CallsReturn`], [58,984],
    [`ExtraAnswer`], [Assumption dropped: the server writes an answer twice], [finds `ResponseMatch`], [26,406],
    [`ExtraAnswerChecked`], [Not the code: the echoed request identifier compared, the server writes an answer twice], [holds], [1,190,081],
    [`Once`], [Before the fix: a one-shot interrupt and `esdm_invoke`], [finds `RanOnce`], [4,288],
    [`ReadErr`], [Before the fix: a failed read keeping the socket], [finds `ResponseMatch`], [28,731],
    [`Hog`], [Before the fix: the wait for a connection past the deadline], [finds `DeadlineNoWait`], [62],
    [`NoReset`], [Mutation: the socket of an abandoned request kept], [finds `ResponseMatch`], [4,147],
    [`NoOwnerDeadReset`], [Mutation: no reset on `EOWNERDEAD`], [finds `ResponseMatch`], [7,079],
    [`NotRobust`], [Mutation: plain mutexes, a thread canceled in `read()`], [finds a deadlock], [2,699],
  ),
  caption: [Configurations of the #ac("RPC") client model and their results],
) <tab:fv-rpc-client-results>

Every configuration runs with the deadlock check. The configurations marked
slow are left out of the default run. The state count of a configuration
that finds a violation is that of one run with three workers and varies
between runs.

#paragraph[Findings][Every path that abandons a request in flight closes
the socket: an interrupt in the read, a spent receive budget, a connection
closed by the server and `EOWNERDEAD` on the lock of a canceled owner.
Mutations that keep the socket on these paths break `ResponseMatch`
(configurations `NoReset` and `NoOwnerDeadReset`). Model checking found two
gaps and the review of the code found a third, which the model shows as well. All
three are fixed; the configurations `Once`, `ReadErr` and `Hog` keep the code
before the fix:]

- An interrupt in the read reported `-EINTR` for every call, and the
  documentation and `esdm_invoke` repeat a call on `-EINTR`. The request had
  reached the server, which may have run it: with an interrupt function that
  reports once, `esdm_invoke` sent `esdm_rpcc_rnd_add_entropy` again and the
  entropy was credited twice (`Once`, `RanOnce`), although
  `esdm_client_invoke` itself never re-sends such a request. For the six
  requests that must not run twice, `esdm_client_invoke` now reports such an
  interrupt as `-ETIMEDOUT`, the outcome being unknown as for a lost answer,
  and their documentation states that they must not be repeated in that case
  (`OnceFixed`, `OnceSticky`).
- `esdm_rpc_client_read_handler` kept the socket when `read()` failed with an
  errno other than `EAGAIN`, `EINTR` and `ECONNRESET`, with the request in
  flight; were the failure transient, the next call on the connection would
  have taken that answer (`ReadErr`, `ResponseMatch`). Linux reports no such
  errno on a connected socket of this kind, so the gap was latent. A failed
  read now closes the socket (`ReadErrFixed`).
- `esdm_rpcc_get_random_bytes_full_timeout` waited for a pooled connection
  without bound when all were checked out, past its deadline for as long as
  another caller kept one (`Hog`, `DeadlineNoWait`). The wait now ends at the
  deadline, with `mutex_w_timedlock` (`HogFixed`).

#paragraph[Limits][Three statements hold under an assumption only, and one
configuration each removes it:]

- The client does not compare the request identifier or the method index of
  a response with those of its request. Were the server to write an answer
  twice, the client would take the second one for the answer to its next
  request on that socket and would not notice (`ExtraAnswer`,
  `ResponseMatch`). The server code writes one response per request and
  closes the connection when the write fails, so this is no defect of the
  two together; the match of request and response is, however, not checked
  end to end. A comparison of the echoed identifier, which the code does
  not contain, would refuse such an answer and fail the call
  (`ExtraAnswerChecked`).
- With threads that call without end, a thread waiting for the `ref_cnt`
  mutex of its home connection can wait permanently when the mutex is only
  weakly fair: the other thread returns the connection and takes it again
  with `mutex_w_trylock` each time (`Starve`, `CallsReturn`). Freedom from
  starvation therefore rests on the mutex implementation and is not a
  property of the client code (`Fair`).
- With plain instead of robust mutexes, a thread canceled in `read()` keeps
  `ref_cnt` and `lock`, and the next caller of that connection hangs
  (`NotRobust`, found by the deadlock check).

The configurations with a pool of two connections and three threads
(`Pool3`, `LivePool3`) are the only ones in which a thread waits for its
home connection while another connection is used; with two threads on two
connections the first pass always finds a free one.

=== Entropy Buffer of the Kernel Module esdm_es <sec:fv-kernel-es>

`tests/tla/EsdmKernelEs.tla` models the per-CPU event rings of
`kernel/esdm_es/esdm_es_ring.c`, filled by the interrupt and scheduler hooks
through `esdm_time_process` and the #ac("SP") 800-90B health tests of
`esdm_health.c`, and emptied by the #ac("IOCTL") reader through
`esdm_es_drbg_pool_extract`, together with the resets by health test
failures, the reboot, power management and #ac("VM") generation notifiers
and module exit.

#paragraph[Model][Two #ac("CPU", pl: true), in four configurations three,
carry a ring each, with its write and read position, the staged read position
of an extraction and its generation, and the ring lock. A producer in hard
interrupt context runs per #ac("CPU"); in other configurations the scheduler
hook runs in task context with an interrupt nesting into it, as
`esdm_sched_randomness` sees it from `try_to_wake_up`. A sample may fail the
#ac("APT") or the #ac("RCT") and may end an #ac("APT") window, so that a
failure, the window of the failure and the start-up test that follows it take
any number of samples. The start-up counter starts at zero, the start-up test
passed before, at `ESDM_SP80090B_STARTUP_BLOCKS` as in the code, or one above
it, within the window of a failure. Each access of the health tests to the
counter and to the count of changes in progress is a step, among them the
read by which `esdm_sp80090b_startup` returns early. The reader reads the
generation, checks the start-up test and the available events, collects,
hashes and releases each block, and checks the start-up test and compares
the generation once more; a seed or generate operation of its #ac("DRBG") may
fail. The model follows the contexts as far as the locking relies on them: an
interrupt starts only with interrupts enabled on its #ac("CPU"), a task
context does not step while an interrupt runs on its #ac("CPU"), and the ring
lock disables interrupts and preemption.]

#paragraph[Abstractions][Timing values, the timer #ac("GCD") and the
oversampling arithmetic are left out: a slot holds a ghost event that records
whether it is unused and when it was sampled relative to the failures and
resets, and a block is credited when it collected the events it needs. One
or two readers stand for the descriptors of the device, which the
#ac("IOCTL") mutex serializes. Within a sample, the failure precedes the end
of the window, as in the #ac("APT"); the #ac("RCT") failure of a sample that
ended a window is modeled as the failure of the next sample of that
#ac("CPU"). #ac("CPU") hotplug, the permanent failure and the panic, the
deferred messages and the registration work are not modeled. Every context
is bounded: producers take a number of samples, readers issue a number of
requests, and all of them end.]

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`NoOverrun`], [A producer never writes a slot that holds an event not
      consumed.],
    [`NoStaleCredit`, `HashIntact`], [Every credited block hashed events that
      were never handed out or discarded before, and none of its slots was
      overwritten between collection and hash: no double credit when
      producers, reader and resets race.],
    [`CreditBound`], [The entropy credited never exceeds the events the
      producers stored, each passed by the health tests.],
    [`NoEventLost`], [Every event stored is in a ring until a block that
      hashed it is released or a reset discards it: the rings lose no event
      and hand none out twice. By design, an event that finds its ring full
      is not stored, and the events of a released block are consumed also
      when the #ac("DRBG") or the request fails afterwards.],
    [`NoPreResetCredit`], [No credited event was sampled before a reset that
      completed before the request compared the generation at its end, be it
      before the request or during it, except for an event stored
      concurrently with a reset.],
    [`NoPreFailureCredit`], [No credited event was sampled before a health
      test failure that preceded the last start-up check of the request, with
      the same exception.],
    [`NoWindowCredit`], [No credited event was sampled within the #ac("APT")
      window of a failure, which the completion of the window discards, with
      the same exception.],
    [`NoWindowCreditStrict`], [`NoWindowCredit` without the exception: no
      credited event was sampled within the window of a failure at all. It
      does not hold, by design (`Survivor`).],
    [`FailureDiscards`], [Once `esdm_sp80090b_startup_restart` did the reset
      of the first failure of a window, no ring holds an event sampled before
      that failure, with the same exception.],
    [`WindowDiscards`], [Once `esdm_sp80090b_startup` did the reset at the
      end of the window of a failure, no ring holds an event sampled within
      that window, with the same exception.],
    [`StartupGate`], [Nothing is credited before the start-up test passed for
      the first time.],
    [`NoIdleChange`], [While the start-up test has passed and no failure
      began, no change of the start-up test is in progress: a window that
      ends at run time fails no request.],
    [`SurvivorBound`], [A reset leaves at most one event per producer context
      of a #ac("CPU"): the one stored concurrently with it.],
    [`NoSelfDeadlock`], [No interrupt spins on the ring lock held by a task
      context of its own #ac("CPU").],
    [`NoUseAfterFree`], [No hook writes a ring after module exit freed it:
      `synchronize_rcu` waits for the hooks still running.],
    [No deadlock], [No state is reached in which a context waits and no
      other context can step. As every context is bounded, a context that
      waits forever for a lock, the mutex or the hooks ends in such a
      state.],
    [`Termination`], [Under weak fairness, every context finishes: no
      request, hook, notifier or module exit waits forever.],
  ),
  caption: [Properties of the `esdm_es` buffer model],
) <tab:fv-kernel-es-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Health` (slow)], [A failure, its window and the start-up test with the fix], [holds], [10,030,779],
    [`Failure`], [A failure while a request runs], [holds], [485,696],
    [`WindowEnd`], [The end of the window of a failure and the last window of the start-up test, starting within that window], [holds], [216,425],
    [`SecondFailure`], [A further failure within the window of a failure], [holds], [5,659,955],
    [`ThreeCpus`], [Three #ac("CPU", pl: true), two resets outstanding at once, under the state constraint `TwoStalled`], [holds], [3,106,042],
    [`ThreeCpusWide` (slow)], [Three #ac("CPU", pl: true), the order free, under the state constraint `FewSamples`], [holds], [21,539,246],
    [`ThreeCpusFull` (slow)], [Three #ac("CPU", pl: true) without constraint, one sample each and one event per block], [holds], [125,689,609],
    [`Boot`], [The start-up test from the initial value of the code, no failure], [holds], [28,737],
    [`Startup` (slow)], [The same with a failure during or after it, its window and the start-up test again], [holds], [9,780,970],
    [`Idle`], [Windows that end at run time, without a failure], [holds], [26,836],
    [`Resets`], [Notifier resets, failing seeds, two blocks of one event], [holds], [261,348],
    [`Discard`], [A collection that finds too few events after a reset, then a second request], [holds], [2,798,122],
    [`TwoReaders`], [Two readers serialized by the #ac("IOCTL") mutex, a notifier reset], [holds], [955,890],
    [`Sched`], [The scheduler hook and a nested interrupt, interrupts off as in the code], [holds], [23,220],
    [`Unload`], [Module exit: the hooks unregistered, `synchronize_rcu`, the arrays freed], [holds], [7,677],
    [`Atomic`], [Alternative fix: the change of the start-up test and its reset under the ring lock], [holds], [2,526,296],
    [`Survivor`], [The sample stored concurrently with a window's reset (documented)], [finds `NoWindowCreditStrict`], [139,513],
    [`Window`], [Before the fix: an event sampled after a failure, before its reset], [finds `NoWindowCredit`], [114,915],
    [`Stall`], [Before the fix: the final start-up check alone, a late window reset], [finds `NoWindowCredit`], [2,647,262],
    [`NoPendWin`], [Mutation: a failure counts as a change in progress, the end of a window does not], [finds `NoWindowCredit`], [157,169],
    [`NoFinalPend`], [Mutation: the final check does not read the count of changes in progress, three #ac("CPU", pl: true)], [finds `NoWindowCredit`], [1,949,790],
    [`NoEarlyReturn`], [Mutation: the end of a window counts as a change also after the start-up test], [finds `NoIdleChange`], [75],
    [`NoGate`], [Mutation: no check of the start-up test, from the initial value of the code], [finds `StartupGate`], [17,344],
    [`NoFailReset`], [Mutation: a failure does not reset the rings], [finds `FailureDiscards`], [711],
    [`NoWinReset`], [Mutation: the end of the window of a failure does not reset the rings], [finds `WindowDiscards`], [938],
    [`Nested`], [Mutation: interrupts on in the scheduler hook], [finds `NoStaleCredit`], [33,310],
    [`Lost`], [The same mutation: an event is lost], [finds `NoEventLost`], [1,020],
    [`NoIrqSave`], [Mutation: the ring lock taken with interrupts on], [finds `NoSelfDeadlock`], [214],
    [`Spin`], [The same mutation without that invariant: the spinning interrupt as a deadlock], [finds a deadlock], [3,170],
    [`Hang`], [The same without the deadlock check: the spinning interrupt never returns], [finds `Termination`], [18,953],
    [`NoMutex`], [Mutation: two readers without the #ac("IOCTL") mutex], [finds `NoStaleCredit`], [94,146],
    [`NoRcu`], [Mutation: module exit without `synchronize_rcu`], [finds `NoUseAfterFree`], [1,211],
  ),
  caption: [Configurations of the `esdm_es` buffer model and their results.
    Every configuration but `Hang` checks for deadlocks. The state count of a
    configuration that finds a violation is that of one run with three
    workers and varies between runs],
) <tab:fv-kernel-es-results>

#paragraph[Findings][The buffering holds: the rings lose or duplicate no
event (`NoEventLost`), and no credit exceeds the events collected, also with
resets at any point of an extraction. The health test gate did not hold in
two interleavings, both of low severity:]

- `esdm_sp80090b_startup_restart` re-arms the start-up test with an
  `atomic_xchg` and then resets the rings, whose generation changes under the
  ring lock. The request assumed that the generation changes before it reads
  it at the end. If the failing #ac("CPU") reached the ring lock only after
  that, the request credited events that another #ac("CPU") sampled after the
  failure, while the start-up test ran again (configuration `Window`, property
  `NoWindowCredit`).
- `esdm_sp80090b_startup` decrements the start-up counter and then resets the
  rings when the window of a failure completed. If the #ac("CPU") that
  completed the window was delayed between the two, while the other
  #ac("CPU", pl: true) passed the remaining start-up windows, a request
  credited the samples of the failure window before they were discarded, also
  with the start-up test checked again at the end (`Stall`). This
  interleaving requires a #ac("CPU") stalled in interrupt context for
  `ESDM_SP80090B_STARTUP_BLOCKS` windows of samples, which a hypervisor
  descheduling a virtual #ac("CPU") can cause.

Both are fixed: each change of the start-up counter counts as a reset in
progress from before the change until after its reset, a reset in progress
fails `esdm_sp80090b_startup_complete_es`, and `esdm_es_drbg_pool_extract`
checks the start-up test again before it compares the generation at the end
(`PendReset` with `PendWin`, `FinalCheck` with `FinalPend`; configurations
`Health`, `Failure`, `WindowEnd`, `SecondFailure` and `ThreeCpus`).
`esdm_sp80090b_startup` returns early while the counter reads zero, before
it counts a change in progress, so that a window that completes after the
start-up test does not fail a concurrent request: `NoIdleChange` holds, and
fails without the early return (`NoEarlyReturn`). `Window` and `Stall` keep
the code before the fix. Changing the counter and the generation in one
critical section of the ring lock closes both as well (`AtomicReset`,
configuration `Atomic`), but requires the health tests to access the rings of
both entropy sources.

The configurations and mutations of the model show which parts of the fix
the properties depend on:

- The end of a window has to count as a change in progress, and the count
  has to end after the reset. With failures counted alone, the second
  interleaving returns (`NoPendWin`, with two #ac("CPU", pl: true), starting
  within the window of a failure); with the count of the window ended before
  its reset, `WindowEnd` fails.
- The final check has to read the count of changes in progress, not only the
  counter. The configurations with two #ac("CPU", pl: true) hold without
  that read. With three, one #ac("CPU") stalls in the failure before its
  reset and a second one at the end of the window before its reset, while
  the third passes the start-up test: the counter reads zero, the generation
  is unchanged, and the request credits an event of the failure window
  (`NoFinalPend`). `ThreeCpus` holds with the read, under a state constraint
  that selects this scenario: only the first #ac("CPU") fails, and the
  others sample after that failure, which follows the start of the request.
  `ThreeCpusWide` keeps the roles of the three #ac("CPU", pl: true) and
  leaves the order free, with two samples of the third #ac("CPU") and two
  events per block; it fails without the read as well. `ThreeCpusFull` has
  no constraint, with one sample per #ac("CPU") and one event per block.
  Three #ac("CPU", pl: true) with two samples each and no constraint are
  not among the configurations: a run was stopped after 37 minutes at
  102 million states and depth 34, without a violation and with the number
  of states to explore still growing.
- The final read of the counter and the count of a failure as a change in
  progress cover each other. With either one removed, `Failure`,
  `SecondFailure`, `ThreeCpus` and `Health` hold; with both removed,
  `Failure` fails. The code has both.
- The first check of the start-up test is not needed for the properties of
  the model once the final check is in place: without it, `Failure`,
  `WindowEnd`, `Boot`, `SecondFailure`, `ThreeCpus` and `Health` hold. It
  keeps a request from collecting, and thereby consuming, events while the
  start-up test runs. Without both checks, a request is credited during the
  first start-up test (`NoGate`).
- The reset at the failure itself is not needed for the properties of a
  request either: the end of the failure's window discards the events
  before the start-up test can pass again, and `Failure`, `ThreeCpus` and
  `Health` hold their other properties without it. `FailureDiscards` states what
  this reset adds, that no event from before the failure stays in a ring
  once `esdm_sp80090b_startup_restart` returned, and fails without it
  (`NoFailReset`); `WindowDiscards` states the same for the reset at the end
  of the window (`NoWinReset`). A further failure within the window does not
  reset, as in the code (`SecondFailure`).

`Boot` and `Startup` start from the initial value of the counter in the
code, the other configurations with a start-up test that passed before or
within the window of a failure: nothing is credited before the start-up test
passed for the first time (`StartupGate`).

The model is sequentially consistent; the code gets the order it relies
on from fully ordered atomic operations, `smp_mb__after_atomic` and
`smp_mb__before_atomic` around the count of changes in progress, and acquire
reads in `esdm_sp80090b_startup_complete_es`. A litmus test states this order
(`tests/litmus/esdm-startup-window.litmus`): checked with `herd7` against the
memory model of the Linux kernel, a reader never takes the start-up test as
passed while the reset of a completed failure window is outstanding. A second
litmus test swaps the two reads of one call of
`esdm_sp80090b_startup_complete_es` and is violated; it shows that a single
call is consistent only in this order, not that the request as a whole
depends on it – with the two reads swapped in both checks, the model still
holds, as the final check follows the first one.

The configurations without interrupts disabled in the scheduler hook
(`Nested`, `Lost`), with the ring lock taken with interrupts enabled
(`NoIrqSave`), with module exit not waiting for the hooks (`NoRcu`) and with
two readers outside the #ac("IOCTL") mutex (`NoMutex`) show that the code
needs each of these: an interrupt's nested call of the hook moves the write
position back, so that an event is lost and stale slots are credited, the
interrupt spins on the lock its #ac("CPU") holds, a hook writes a freed
array, and both readers credit the same events. The further guards of the
ring have no switch in the model; each was removed in a copy of the model,
and a configuration that is not slow fails: the check for a full ring
(`Sched`), the comparison of the generation in `esdm_es_ring_release` and at
the end of the request (`Resets`), a reset that skips a ring (`Failure`) and
the pending mask that `esdm_es_ring_discard` clears (`Discard`). The event a
producer stores concurrently with a reset survives it, as the comment of
`esdm_es_ring_reset` states, and is credited later, also after a failure and
the start-up test (`Survivor`); `SurvivorBound` holds.

Each property of table @tab:fv-kernel-es-properties was seen to fail. Those
that table @tab:fv-kernel-es-results names fail in their configuration.
`NoOverrun` and `HashIntact` fail with the constants of `Nested`, and
`CreditBound` with those of `NoMutex`, when listed alone.
`NoPreResetCredit`, `NoPreFailureCredit` and `SurvivorBound` fail under a
mutation in a copy of the model: a request that does not compare the
generation at its end, a final check without the read of the counter
together with a failure that does not count as a change in progress, and a
reset that leaves a ring alone.

Every configuration but one checks for deadlocks. `Termination` is checked
in addition by `Failure`, `WindowEnd`, `Idle`, `Boot`, `Resets`, `Sched` and
`Unload`; it is left out of the larger configurations for their run time and
of those with a state constraint, which cuts behaviors short. As every
context of the model is bounded and no step repeats, the deadlock check finds
a context that waits forever there as well: with the ring lock taken with
interrupts enabled, the interrupt that spins on the lock is reported as a
deadlock once the other contexts ended (`Spin`). `Hang` is the same
configuration with `Termination` and without the deadlock check, which TLC
would report first: the property fails.

=== Character Devices of the Kernel Module esdm_cdev <sec:fv-kernel-cdev>

`tests/tla/EsdmKernelCdev.tla` models `esdm_cdev_read` and the poll functions
of `kernel/esdm_cdev/esdm_cdev_main.c`: the flag that the #ac("ESDM") is
operational, the readers waiting for it in `esdm_cdev_wait_operational`, the
watcher `esdm_cdev_watch`, and the 50 ms during which `/dev/esdm_pr` reports
itself not readable after a prediction resistant read that found nothing.

#paragraph[Model][Readers of `/dev/esdm_random`, `/dev/esdm_urandom` and
`/dev/esdm_pr`, blocking or with `O_NONBLOCK`, readers of `/dev/esdm_random`
with `O_SYNC`, and pollers of `/dev/esdm_random` and `/dev/esdm_pr` run
concurrently with the watcher and the wake work of `/dev/esdm_pr`, both
delayed work items. A request to the #ac("ESDM") is one step with the
contract of `esdm_cdev.h` – data, nothing, an error, or `-ERESTARTSYS` with a
signal pending – and its caller acts on the answer in later steps. The wait
queues follow the kernel: a waiter is queued before it checks its condition,
unless a signal is pending, and is removed by its wakeup; a poller stays
queued until its `poll` returns. The allocation of a read may fail, and the
50 ms a blocking prediction resistant read sleeps may end early without a
signal.]

#paragraph[Abstractions][Until the environment turns good, the #ac("ESDM")
stops, restarts, turns operational or not and runs out of prediction
resistant data at any time, every request may fail or come back empty, and
signals arrive; once good, the #ac("ESDM") is reachable and operational and
nothing changes any more. The environment may turn good at any time and need
not ever. Time is a flag for the 50 ms, and one step of time ends the 50 ms
of every read before it; the delays of the watcher are left out. A read asks
for one chunk, a `poll` waits for readability without timeout or signal.
Writes, the #ac("IOCTL", pl: true) and `/proc/esdm` are not modeled.]

#paragraph[Deadlock and liveness][Every configuration is checked for
deadlocks but `HangLive`, which expects the liveness property to fail on the
hang that the check would report first. A good environment with every read and `poll`
returned idles in an explicit step; every other state without a successor is
reported. The environment can always step before it turns good, but turning
good is one of these steps and leaves the module as it is: a hang of the
module before that is a deadlock in the successor state. The liveness
properties assume weak fairness of every reader, poller and work item and of
the passing of the 50 ms.]

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`ReadResult`], [A read returns data, `EAGAIN`, `ERESTARTSYS`, `ENOMEM`
      or, from `/dev/esdm_urandom`, the error of the request: a blocking read
      of `/dev/esdm_random` or `/dev/esdm_pr` waits for an #ac("ESDM") it
      cannot reach, and a read of `/dev/esdm_pr` with `O_NONBLOCK` returns
      data or `EAGAIN` only.],
    [`RestartSignal`], [A read returns `ERESTARTSYS` only with a signal
      pending.],
    [`PrBackoff`], [After a prediction resistant read with `O_NONBLOCK`
      returned `EAGAIN` because it found nothing – no data or no memory, no
      signal –, the poll function of `/dev/esdm_pr` does not report the
      device readable until 50 ms after the read found nothing, or until a
      read records data. The obligation is recorded when the read returns
      and checked when the poll function decides.],
    [`WaitersCount`], [The count of waiters equals the readers in
      `esdm_cdev_wait_operational`.],
    [`WaitQueue`], [A reader on the wait queue is in its wait, a poller on a
      wait queue is in its `poll`.],
    [`NoLostWakeup`], [Once the #ac("ESDM") is good, no reader sleeps for it
      to turn operational while nothing but time can happen.],
    [`ReadsReturn`, `PollsReturn`], [Once the #ac("ESDM") stays good, every
      read returns and every `poll` returns readable.],
    [`SignalEnds`], [A read with a signal pending returns, whatever the
      state of the #ac("ESDM").],
    [`WatcherStops`], [Once every read and `poll` has returned, the watcher
      stops asking the #ac("ESDM"), whatever its state.],
    [`SyncBackoff`], [`PrBackoff` for the poll function of
      `/dev/esdm_random` on a file opened with `O_SYNC`. The code does not
      deliver it; only `SyncPoll` lists it.],
  ),
  caption: [Properties of the `esdm_cdev` device model],
) <tab:fv-kernel-cdev-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Kick`], [A blocking and a non-blocking reader of `/dev/esdm_random`, liveness (slow)], [holds], [639,303],
    [`KickSafety`], [As `Kick`, invariants and deadlock only], [holds], [639,303],
    [`WaitSignal`], [A blocking reader of `/dev/esdm_random`, a signal ends its wait, liveness], [holds], [49,014],
    [`WaitSignalKick`], [As `Kick` with a signal, liveness (slow)], [holds], [2,336,957],
    [`Poll`], [A poller of `/dev/esdm_random` next to a non-blocking reader, liveness], [holds], [54,509],
    [`Pr`], [`/dev/esdm_pr` polled and read with `O_NONBLOCK`, as QEMU does, a signal, liveness], [holds], [149,842],
    [`PrAlloc`], [As `Pr` without signal, the read may get no memory, liveness], [holds], [88,816],
    [`PrBlock`], [Blocking and non-blocking readers of `/dev/esdm_pr`, a signal, liveness (slow)], [holds], [430,066],
    [`PrBlockSafety`], [As `PrBlock`, invariants and deadlock only], [holds], [430,066],
    [`PrSleep`], [A blocking reader of `/dev/esdm_pr` woken early, a signal, no memory, liveness], [holds], [11,648],
    [`Sync`], [A non-blocking reader of `/dev/esdm_random` with `O_SYNC`, a poller of `/dev/esdm_pr`, a signal, liveness], [holds], [149,842],
    [`SyncBlock`], [Blocking and non-blocking readers of `/dev/esdm_random` with `O_SYNC`, a signal, liveness (slow)], [holds], [430,066],
    [`Urandom`], [Blocking and non-blocking readers of `/dev/esdm_urandom`, liveness (slow)], [holds], [345,002],
    [`UrandomSafety`], [As `Urandom`, invariants and deadlock only], [holds], [345,002],
    [`Hang`], [Before the fix: a late "not operational" of a non-blocking read], [finds `NoLostWakeup`], [160,030],
    [`HangDeadlock`], [As `Hang` without `NoLostWakeup`], [finds a deadlock], [182,960],
    [`HangLive`], [As `Hang` without `NoLostWakeup` and the deadlock check (slow)], [finds `ReadsReturn`], [206,320],
    [`PrAllocOld`], [Before the fix: `EAGAIN` without memory leaves `/dev/esdm_pr` readable], [finds `PrBackoff`], [8,996],
    [`PrSleepOld`], [Before the fix: an early wakeup without a signal], [finds `RestartSignal`], [1,281],
    [`SyncPoll`], [`poll` of `/dev/esdm_random` with `O_SYNC` after an empty read], [finds `SyncBackoff`], [12,655],
  ),
  caption: [Configurations of the `esdm_cdev` device model and their results],
) <tab:fv-kernel-cdev-results>

#paragraph[Findings][A blocking read could sleep permanently: every
non-prediction-resistant read sets the operational flag from its own answer,
and `esdm_cdev_set_operational` cleared the flag without any wakeup or kick.
A non-blocking read that got its empty answer before the #ac("ESDM") turned
operational and cleared the flag after the watcher set it left the watcher
stopped – it stops once the flag is set – and a blocking reader of
`/dev/esdm_random` that checked the flag then slept with nothing left to wake
it, until a signal or another reader or poller of the module arrived
(configurations `Hang`, `HangDeadlock` and `HangLive`, which keep the code
before the fix and find the hang by the invariant, the deadlock check and the
liveness property). `esdm_cdev_set_operational` now kicks the watcher when it
clears the flag while a reader waits (`KickOnUnset`). Of its three callers
only the read needs the kick: with the kick removed there, `KickSafety`
violates `NoLostWakeup`; removed in `esdm_cdev_wait_operational` or in the
watcher, `KickSafety` holds, as the first kicks the watcher unconditionally
afterwards and the second queues itself again while somebody waits.]

Two further defects of `esdm_cdev_read` are fixed. A read of `/dev/esdm_pr`
with `O_NONBLOCK` that got no memory returned `EAGAIN` without arming the
back-off, so that `poll` kept reporting the device readable (`PrAllocOld`);
it now arms it (`AllocBackoff`, configuration `PrAlloc`). A blocking
prediction resistant read took every early end of its 50 ms sleep for a
signal and returned `ERESTARTSYS`, which reaches the caller unchanged when no
signal is pending (`PrSleepOld`); the read now continues, and its loop ends
it when a signal is pending (`SleepFix`, configuration `PrSleep`). The
module with both changes builds against the oldest and the latest supported
kernel and passes the `cdev` virtual machine test; that test reaches neither
of the two paths.

The back-off is that of `/dev/esdm_pr` only. A read of `/dev/esdm_random`
with `O_SYNC` arms and ends it as a read of `/dev/esdm_pr` does (`Sync`), but
`esdm_cdev_poll` does not look at the file flags: a caller that polls
`/dev/esdm_random` through a file opened with `O_SYNC | O_NONBLOCK` and reads
whenever it is readable is not held back after an empty read (`SyncPoll`),
and `/dev/esdm_urandom` has no poll function. The code is left as it is;
such a caller has `/dev/esdm_pr`.

`PrBackoff` is violated by a poll function that ignores the back-off and by
a read that does not arm it (`Pr`, `Sync`); without the wake work the poller
deadlocks (`Pr`, `PrAlloc`). A signal exit of the wait that keeps the count
of waiters or the queue entry violates `WaitersCount` or `WaitQueue`, a wait
that ignores the signal `SignalEnds`, and a watcher that queues itself with
nobody waiting `WatcherStops` (`WaitSignal`, `Poll`). These mutations were
run on copies of the model and are not shipped configurations. A read that
gets data and does not end the back-off violates nothing: the device then
turns readable up to 50 ms late.

=== Connections of the Kernel Module esdm_cdev <sec:fv-kernel-cdev-conn>

`tests/tla/EsdmKernelCdevConn.tla` models `esdm_cdev_invoke` of
`kernel/esdm_cdev/esdm_cdev_egd.c`: the pool of connections with its exclusive
wait queue, the connect on the workqueue with its completion and reference
count, the backoff, and restarts of the #ac("ESDM").

#paragraph[Model][Tasks take a connection with `esdm_cdev_conn_get`, connect
it when needed through a connect work, send a request tagged with the task
and a bit flipped per request, and read the answer, which the #ac("ESDM")
echoes; a failed request drops the socket and is made once more on a fresh
one after the #ac("ESDM") closed the connection, unless it is a privileged
command that went out. `esdm_cdev_conn_try` is one `mutex_trylock` per step,
so that with several connections one can be freed behind the scan of a task.
Until the environment turns good the #ac("ESDM") restarts, closes single
connections, possibly after carrying out the command it read, refuses
connects while down, and every wait may time out or be interrupted by a
signal; the answer to a privileged command is waited for despite signals. A
task repeats a call that failed, as a blocking read does, but not one a
signal ended. The call of a privileged command that a signal ended before the
command went out either returns to user space or is restarted by the kernel,
and is then the same command to the #ac("ESDM"). A privileged command the
#ac("ESDM") has not read when the module closes the connection stays with
the #ac("ESDM"), which may still carry it out.]

#paragraph[Abstractions][A socket is the state of one connection;
`sock_release` discards the answers, and the read requests the #ac("ESDM")
has not taken yet. Sockets are counted, one more with each connect that succeeds and one
less with each `sock_release`, and the pointers to them are flags. The
#ac("ESDM") reads and answers a request in one step; the backoff is a flag
that time clears; restarts, closes and timeouts are bounded in number. A
connect work is one of a bounded number of slots, and its allocation fails
only when none is free. A scan for a free connection starts at any
connection. Answers that do not fit the protocol, partial sends, fatal
signals and module unload are not modeled.]

#paragraph[Termination][The model ends when every task has made its calls:
the environment then idles in a step of its own, the only state from which
nothing else can happen. The faults, the signals, the restarts and the
passing of the backoff are bounded, so that no step of the environment hides
a task that hangs, and a task that sleeps for good is a deadlock
(`NoPassOnDeadlock`). Every configuration checks for deadlocks, except
`NoPassOnReturn` and `NoPassOnSucceed`: they expect a temporal property to
fail on a mutation whose hang is that deadlock, which TLC would report
first.]

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Property], [Statement]),
    [`ResponseMatch`], [Every answer a request reads is the answer to that
      request: a reader never gets the data of another one, whatever was
      interrupted, timed out or restarted before.],
    [`SentOnce`], [A privileged command is carried out at most once, counted
      at the #ac("ESDM") and including what it carries out of connections the
      module has closed: a command that went out is not sent again, neither by
      `esdm_cdev_invoke` nor by a restart of the system call. The property is
      listed only in configurations with a privileged task.],
    [`AnswerAwaited`], [No call of a privileged command ends with `-EINTR`:
      the answer to a command that went out is waited for despite signals.
      The code keeps `-EINTR` for a fatal signal, which the model does not
      have. Listed with `SentOnce`.],
    [`ExclusiveUse`], [A connection serves one request at a time: no two
      tasks have the same connection, and what is on its way on a connection,
      in either direction, is the one request of the task that has it, or the
      answer to it.],
    [`NoSockLeak`], [The sockets that exist are those of the connections and
      those of the connects no waiter has taken yet: none is left behind and
      none is released twice. The reference count of a connect is the number
      of its users, the waiter and the work, and the connect is freed with the
      last reference.],
    [`NoStaleEntry`], [The entries of the wait queue are those of tasks in
      `esdm_cdev_conn_get`, one each: an entry lives on the stack of that
      function.],
    [`NoStrandedWaiter`], [Once the #ac("ESDM") is good, no task sleeps for a
      connection while nothing but time can happen.],
    [`NoSleeperByIdlePool`], [No task sleeps for a connection while all of
      them are free, except while a wakeup is on its way or a task is about to
      look for a connection: while tasks sleep, a connection is in use, and
      its release wakes one of them.],
    [`NoSleeperByFreeConn`], [The same while any connection is free. It holds
      with one connection and not with several (see the findings); it is
      listed in the configurations with one connection and in `WakeNext2`.],
    [`CallsReturn`, `CallsSucceed`], [Once the #ac("ESDM") stays good, every
      call returns, and every task gets its answers: connections closed by a
      restart are made anew and the backoff ends. Weak fairness of every
      process suffices.],
  ),
  caption: [Properties of the `esdm_cdev` connection model],
) <tab:fv-kernel-cdev-conn-properties>

#figure(
  table(columns: (auto, 1fr, auto, auto), align: left + horizon,
    table.header([Configuration], [Checks], [Result], [States]),
    [`Pool`], [Three tasks on one connection that is connected, a signal, liveness], [holds], [87,090],
    [`Pool2`], [Four tasks on two connections, a signal (S)], [holds], [841,010],
    [`Pool2Live`], [Three tasks on two connections, liveness], [holds], [36,412],
    [`Pool3`], [Four tasks on three connections, a signal (S)], [holds], [1,075,798],
    [`Pool4`], [Five tasks on four connections, the number of the code (S, slow)], [holds], [2,358,400],
    [`Pool4Signal`], [The same with a signal (S, slow, 50 minutes)], [holds], [23,951,232],
    [`Signals`], [Two readers on one connection: a fault and a signal], [holds], [992,899],
    [`Fault`], [Two readers on one connection with one connect work: a fault, an allocation that fails, liveness], [holds], [61,995],
    [`Restart`], [Two readers on one connection with two connect works: a fault, liveness], [holds], [164,327],
    [`Restart2`], [Two readers on two connections: a fault (S)], [holds], [1,186,254],
    [`Signals2`], [Two readers on two connections: a fault and a signal (slow)], [holds], [11,744,716],
    [`Contend2`], [Three readers on two connections that are connected: a fault (S, slow)], [holds], [6,911,936],
    [`Connect2`], [Three readers on two connections with two connect works: a fault (S, slow, 42 minutes)], [holds], [61,155,842],
    [`PrivQuick`], [A privileged command next to a reader: a fault and a signal], [holds], [1,348,370],
    [`PrivLive`], [A privileged command alone: a fault and a signal, liveness], [holds], [4,531],
    [`Priv`], [A privileged command next to a reader: two faults and a signal (slow)], [holds], [10,475,145],
    [`WakeNext2`], [Not the code: a waiter that leaves with a connection wakes the next one; four tasks on two connections, a signal (S)], [holds, with `NoSleeperByFreeConn`], [846,314],
    [`ScanRace`], [The code: four tasks on two connections, neither a signal nor a fault (S)], [finds `NoSleeperByFreeConn`], [91,375],
    [`NoPassOn`], [Mutation: a waiter leaving on a signal keeps the wakeup it took; three tasks on one connection], [finds `NoSleeperByFreeConn`], [57,546],
    [`NoPassOnIdle`], [The same mutation], [finds `NoSleeperByIdlePool`], [57,251],
    [`NoPassOnStranded`], [The same mutation], [finds `NoStrandedWaiter`], [79,923],
    [`NoPassOnDeadlock`], [The same mutation], [finds a deadlock], [82,295],
    [`NoPassOnReturn`], [The same mutation, no deadlock check], [finds `CallsReturn`], [87,378],
    [`NoPassOnSucceed`], [The same mutation, no deadlock check], [finds `CallsSucceed`], [87,378],
    [`NoLock`], [Mutation: a connection is taken without `mutex_trylock`], [finds `ExclusiveUse`], [50],
    [`NoDrop`], [Mutation: the connection of an interrupted request is kept], [finds `ResponseMatch`], [2,016],
    [`NoCommit`], [Mutation: a privileged command that went out is made again after the #ac("ESDM") closed the connection], [finds `SentOnce`], [292],
    [`NoCommitSignal`], [Mutation: a privileged command that went out is interrupted and restarted], [finds `SentOnce`], [136],
    [`NoAwait`], [Mutation: the answer to a privileged command that went out is not waited for when a signal comes], [finds `AnswerAwaited`], [58],
    [`NoFinish`], [Mutation: a waiter that got a connection leaves its entry on the wait queue], [finds `NoStaleEntry`], [401],
    [`NoRelease`], [Mutation: the last reference to a connect does not release the socket nobody took], [finds `NoSockLeak`], [71],
  ),
  caption: [Configurations of the `esdm_cdev` connection model and their
    results. S: the tasks are a symmetry set, the count is that of the reduced
    state space. A configuration that finds a violation stops there, its count
    varies from run to run. Where no property is named, a configuration lists
    all safety properties that apply to it, and the liveness properties where
    stated.],
) <tab:fv-kernel-cdev-conn-results>

#paragraph[Findings][With one connection all properties hold. Passing on a
wakeup that a waiter leaving `esdm_cdev_conn_get` took is necessary: without
it, a waiter that a release wakes after its last try, as it leaves on a
signal, takes the wakeup along, and another task sleeps next to the free
connection until its timeout. Every property about waiting then fails, each
in a configuration of its own: `NoSleeperByFreeConn` (`NoPassOn`),
`NoSleeperByIdlePool` (`NoPassOnIdle`), `NoStrandedWaiter`
(`NoPassOnStranded`), the deadlock check (`NoPassOnDeadlock`), `CallsReturn`
(`NoPassOnReturn`) and `CallsSucceed` (`NoPassOnSucceed`).]

#paragraph[Several connections][With several connections the code does not reach what it states as the aim of
passing the wakeup on, that no free connection is left with sleepers
(`ScanRace`: the code as it is, two connections, four tasks, neither a signal
nor a fault). `esdm_cdev_conn_try` looks at one connection after the other. A
waiter finds the first connection busy. That connection is released, and the
wakeup of the release goes to another waiter, queued ahead, which takes the
second connection – released before, and the one the first waiter is about to
look at. The first waiter finds it busy and sleeps, next to the first
connection, which is free. No wakeup is lost: the second waiter got a
connection with the one it took, so it passes nothing on. The first waiter is
woken when that connection is released, or by its timeout; until then a new
request takes the free connection at once, and a waiting one does not. The
delay is one request, at most `timeout_ms`, and needs the release, its wakeup
and the scan of the woken waiter to fall between two `mutex_trylock` of the
first one. What holds with two, three and four
connections is `NoSleeperByIdlePool`, `NoStrandedWaiter` and, with two, the
liveness properties. In the model, a waiter that wakes the next waiter
whenever it leaves with a connection closes the gap (`WakeNext2`,
`NoSleeperByFreeConn` holds with two connections), at the price of a second
wakeup for each release while tasks wait, which moves the task it wakes in
vain to the end of the queue. The code is unchanged: whether the delay is
worth that price, or a scan under the lock of the wait queue, is left open.]

#paragraph[Sensitivity][Each property fails in a configuration of its own,
with one measure of the code switched off by a constant of the model: the
wakeup passed on (`NoPassOn` and the five configurations named after it),
`mutex_trylock` (`NoLock`), the close of a connection whose
request failed (`NoDrop`), the privileged command that is not made again
(`NoCommit`, `NoCommitSignal`), the wait for its answer despite signals
(`NoAwait`), the removal of the wait queue entry (`NoFinish`) and the release
of a socket no waiter took (`NoRelease`). The properties do not rest on the
step that guards them: the commands are counted where the #ac("ESDM") carries
them out, the sockets where they are made and released, and what is on a
connection is compared with who has it.]

#paragraph[Mutations][Further mutations, made on copies of the model and not kept, are found by the
quick configurations: a privileged command made again by `esdm_cdev_invoke`
alone (`PrivQuick`, `SentOnce`); a privileged command that failed and keeps
its connection (`PrivQuick`, `ExclusiveUse`); no second look for a connection
after `prepare_to_wait_exclusive`, a release without its wakeup, and the
wakeup before the unlock (`Pool`, `NoSleeperByIdlePool`); a waiter that gives
up its connect without dropping its reference, a socket taken without
clearing the pointer of the connect, and a work that keeps its reference
(`Signals`, `NoSockLeak`); a path that returns without unlocking (`Signals`
and `Fault`, `NoStrandedWaiter`). One mutation is found only where the code
is changed: a waiter that looks at the first connection of its scan only
after `prepare_to_wait_exclusive` passes `Pool2`, `Pool3` and `Pool2Live` and
fails `WakeNext2`. Only `NoSleeperByFreeConn` asks for the full scan, and
that property does not hold for the code. The backoff is modeled, but no
property states that no connect is made while it lasts; `CallsSucceed` shows
that it ends. The paths the properties depend on are reached: the allocation
that fails in `Fault`, a privileged command carried out after the module
closed its connection, and a restarted call, in `PrivQuick`.]

== Validation of the Models <sec:fv-validation>

A model checked without a violation shows nothing about the code if it does
not do what the code does, or if its properties cannot fail. The models are
validated against both:

- Correspondence: every procedure and label is named after the C function it
  stems from, and the header of each model lists its abstractions and what it
  omits. The steps were derived from the code line by line and checked against
  it; where code and comments disagree, the model follows the code.
- Sensitivity: properties are shown to be able to fail. The demonstrating
  configurations reproduce each defect on the code before its fix, and a
  seeded defect violates properties no earlier revision violated: an
  #ac("RPC") handler that closes instead of replying or answers a privileged
  call without the check (`Mutant`), a kernel connection taken without
  `mutex_trylock` (`NoLock`). Further properties failed with a guard removed
  in a copy of the model, and guards of the fixes were removed in copies to
  confirm that a configuration fails without each; the sections state the
  cases. For the models of `esdm_es` and of the `esdm_cdev` connections this
  covers every property; in the other models, a property for which the
  section names no violation was not shown to fail.
  The deadlock check is shown to report a hang (`Spin` of
  `EsdmKernelEs`, `WorkerExitHang` of `EsdmRpcServer`, `StartRaceIn` of
  `EsdmCuse`). Mutations
  of the code are found: an #ac("EGD") connection left armed while its
  request is deferred (`KeepArmed`), `send` without `MSG_NOSIGNAL`
  (`Sigpipe`), and in the kernel modules interrupts left on in the scheduler
  hook (`Nested`), the ring lock taken with interrupts on (`NoIrqSave`),
  module exit without `synchronize_rcu` (`NoRcu`), readers without the
  #ac("IOCTL") mutex (`NoMutex`) and a wakeup not passed on (`NoPassOn`). Behaviors of earlier revisions are reproduced: the window
  before the forwarded signals were blocked across the fork of the supervisor
  (`Unblocked`), and the threshold per pool that the comment of
  `esdm_aux_get_backtrack` describes (`ThreshPerIter`).
- Non-vacuity: states a property refers to – an emergency reseeding
  over several collections, a deferred #ac("EGD") request with another one
  pipelined behind it, a parked read, a half-closed client – are shown
  to be reachable, so that the invariants on them do not hold merely because
  their premise never occurs.
- Counterexamples against the code: every violation was traced in the C code
  before it was reported, and the fixes in the code follow the fix switches
  of the models. Some were reproduced on the code itself: a harness that runs
  `linux_isolate_namespace_prefork` in a user namespace shows the supervisor
  of the previous revision exiting with `EXIT_FAILURE` and without its cleanup
  when `SIGCHLD` is inherited as ignored, and mirroring the status of the
  daemon after the fix; it also confirms that a forwarded signal the daemon
  has no handler for is dropped. The test `tests/common/linux_pidns_test.c`
  runs it in the same way and kills the supervisor: a daemon that dropped its
  privileges lives on unless it sets the parent-death signal again, as the
  model assumes of the kernel, and ends when it does, when it polls the
  lifeline after the end of the supervisor or has a thread wait at it;
  `tests/server/server_supervisor_test.c` shows the same for `esdm-server`.
  The test suite passes with every fix, and
  the `cdev` virtual machine test with the fix of `esdm_cdev`.
- Composition: where one model relies on another subsystem, it relies on the
  behavior the other model verifies: the #ac("CUSE") model takes from the
  shared memory model the step that stores a status and posts, and the order
  of the version and the post at the start of a server; the self test model
  leaves the seeding to the reseeding model.

== Limitations <sec:fv-limitations>

- Models, not code: the models are written by hand from the code, not
  extracted from it, and no refinement proof connects the two. A step a model
  makes atomic where the code does not, or a path it omits, is a gap the
  checks cannot see. A change of the code needs the model to change with it,
  which nothing enforces.
- Bounded instances: TLC checks every behavior of a finite instance. A defect
  that needs more threads, #ac("DRNG") instances, clients or larger counters
  than the configurations allow stays hidden. The slow configurations extend the
  bounds, but do not remove them. State constraints
  cut some of the larger instances short; a constrained configuration checks
  safety only up to its constraint and no liveness. One instance was given
  up: `EsdmKernelEs` with three #ac("CPU", pl: true), two samples each and no
  constraint did not end within the time allowed (section
  @sec:fv-kernel-es).
- Assumptions: the results rest on the assumptions of section
  @sec:fv-assumptions. Memory orders weaker than sequential consistency,
  faulty locks or kernels, weaknesses of the cryptographic primitives and
  entropy estimates that are too high are outside the models. The barriers of
  the kernel modules are checked by review, not by TLC – but for the health
  gate of `esdm_es`, whose order a litmus test checks against the memory model
  of the kernel (section @sec:fv-kernel-es); #ac("CPU") hotplug is not
  modeled.
- Data and time: data are abstracted to counts, and time to events. The
  models show whether something can happen, not how likely it is or how
  fast. The starvation of the #ac("EGD") worker by one client, for example,
  needs a client faster than the worker; a test on a loaded machine did not
  reproduce it. Throughput, latency and real-time bounds are not covered.
- Liveness: progress holds under fairness and the environment assumptions
  only; a scheduler that starves a thread, or an environment that never
  recovers, is not covered.
- Coverage: the models cover the subsystems for which table @tab:fv-scope
  names a TLA+ model.
  The cryptographic primitives, the entropy sources themselves, the parsers
  and memory safety rest on the methods of chapter @sec:testing. The flake
  check, which #ac("CI") runs, covers the quick configurations; the slow ones
  are run by hand.

== Findings <sec:fv-findings>

Table @tab:fv-findings lists the findings of all models. "Fixed" means that
the code carries the fix and the model checks it; "open" that the code is
unchanged, the model states the behavior, and the fix is a decision about
the design; "mitigated" that the code narrows the defect without closing it;
"by design" that the behavior is intended; "comment fixed" that the code is
unchanged and the comment that stated otherwise is corrected. Behaviors by
design are listed where a property of a model was given up for them. The
severity is "medium" where a local user or an ordinary event can trigger the
defect and a service stops or data is handed out against a stated rule,
"low" where it needs a rare interleaving or a failing system call or its
effect is a bounded delay, and "informational" where nothing but the
statement of the behavior was wrong.

#figure(
  table(columns: (2.2fr, 1fr, auto, auto), align: left + horizon,
    table.header([Finding], [Model], [Severity], [Status]),
    [A failed seed operation counted towards the fully seeded level], [Reseeding], [medium], [fixed],
    [The prediction resistance #ac("DRNG") serves before its initial seed], [Reseeding], [low], [fixed],
    [`esdm_reset` resets the #ac("DRNG", pl: true) before the entropy sources: a seeding in between credits entropy of before the reset], [Reseeding], [medium], [fixed],
    [A collection begun before a reset is credited after it], [Reseeding], [low], [fixed],
    [A waiting request without reseed worker and monitor seeds once and then only waits], [Reseeding], [low], [open],
    [The worker starts due reseeds before bring-ups, which can keep a bring-up waiting], [Reseeding], [low], [open],
    [The self test verdict checked once per request], [Self test], [medium], [fixed],
    [A failed self test does not stop the seedings], [Self test], [low], [fixed],
    [The auxiliary pool self test reads the #ac("XOF") context unlocked], [Self test], [low], [fixed],
    [A self test failing during a generation does not hold back its output], [Self test], [low], [fixed],
    [A chunk that passed its last check is returned after a later failure], [Self test], [informational], [by design],
    [Pool selection mixes the oversampled and the raw count], [Auxiliary pool], [low], [fixed],
    [The oversampling read twice during an extraction], [Auxiliary pool], [low], [fixed],
    [The write wakeup threshold capped only when set], [Auxiliary pool], [low], [fixed],
    [Lookup and extraction not atomic, contrary to a comment], [Auxiliary pool], [informational], [comment fixed],
    [Entropy credited to a pool without state], [Auxiliary pool], [low], [fixed],
    [A failed insertion does not publish the need for entropy], [Auxiliary pool], [low], [fixed],
    [A switch of force_fips at run time does not publish the need for entropy], [Auxiliary pool], [low], [open],
    [The need for entropy published stale], [Shared memory], [low], [fixed],
    [A semaphore rising above 1], [Shared memory], [low], [fixed],
    [The level-triggered post outlives the need, one post for several clients], [Shared memory], [low], [fixed],
    [The ready version published before the state], [Shared memory], [low], [fixed],
    [The snapshot of the initialization outside the lock], [Shared memory], [low], [fixed],
    [A #ac("CUSE") daemon removing the segment of the server], [Shared memory], [medium], [fixed],
    [The cleanup at the exit without `--keep_ipc` racing a starting reader], [Shared memory], [low], [open],
    [`SIGUSR1` before its handler ends the server], [Shared memory], [low], [fixed],
    [The post of the initialization precedes the ready version], [Shared memory], [low], [fixed],
    [The one-shot suspend trigger reaches one of two #ac("CUSE") daemons], [Shared memory], [low], [fixed],
    [A changed write wakeup threshold is not published], [Shared memory], [low], [fixed],
    [A poll without handle drops the registration of a waiter], [#ac("CUSE")], [medium], [fixed],
    [`O_NONBLOCK` ignored by reads], [#ac("CUSE")], [medium], [fixed],
    [Blocking reads occupy every #ac("FUSE") worker], [#ac("CUSE")], [medium], [mitigated],
    [poll ignores the fallback to the kernel device], [#ac("CUSE")], [low], [fixed],
    [A waiting `/dev/urandom` read ignores the #ac("ESDM") stopping], [#ac("CUSE")], [low], [fixed],
    [The suspend trigger reports `POLLIN` early], [#ac("CUSE")], [low], [by design],
    [A starting server takes back the suspend notification of its predecessor], [#ac("CUSE")], [low], [fixed],
    [A suspend notification misses a poll in flight], [#ac("CUSE")], [low], [fixed],
    [A killed server leaves `poll` on its last status], [#ac("CUSE")], [low], [open],
    [The kernel device read through a blocking descriptor: `O_NONBLOCK` waits before the kernel is ready], [#ac("CUSE")], [low], [open],
    [One client holds the worker], [#ac("EGD")], [medium], [fixed],
    [A failing `accept4` spins the worker], [#ac("EGD")], [low], [fixed],
    [The connection limit exceeded by one], [#ac("EGD")], [informational], [fixed],
    [A signal forwarded to the reaped daemon], [Supervisor], [low], [fixed],
    [`SIGCHLD` inherited as ignored], [Supervisor], [low], [fixed],
    [A signal outside the forwarded set ends the supervisor], [Supervisor], [low], [fixed],
    [A #ac("CUSE") stop during the start-up lost], [Supervisor], [low], [fixed],
    [`SIGABRT`, `SIGPIPE` or a fault signal sent to the supervisor ends it], [Supervisor], [low], [fixed],
    [A supervisor ended by `SIGKILL` left a daemon serving on unsupervised], [Supervisor], [low], [fixed],
    [An interrupted request not re-sent is repeated by `esdm_invoke`], [#ac("RPC") client], [low], [fixed],
    [#ac("CUSE") credits the kernel after an outcome left unknown], [#ac("CUSE")], [low], [fixed],
    [A failed read keeps the socket with a request in flight], [#ac("RPC") client], [low], [fixed],
    [The deadline of the timeout call does not bound the wait for a connection], [#ac("RPC") client], [low], [fixed],
    [The echoed request identifier is not compared: a duplicated answer is taken for the next request], [#ac("RPC") client], [low], [open],
    [A call waiting for its connection can be starved by calls that retake it with a trylock], [#ac("RPC") client], [low], [open],
    [A failing eventfd leaves workers on freed memory], [#ac("RPC") server], [medium], [fixed],
    [A lost reply leaves the connection open], [#ac("RPC") server], [low], [fixed],
    [The shutdown deadlocks while the unprivileged workers start], [#ac("RPC") server], [medium], [fixed],
    [A failing `accept4` spins a worker], [#ac("RPC") server], [low], [fixed],
    [A worker leaving on a failure leaves its interface with fewer workers], [#ac("RPC") server], [low], [fixed],
    [A request arriving during the pass of the idle timer is closed unanswered], [#ac("RPC") server], [low], [open],
    [A privileged connection outlives the privilege drop of its client], [#ac("RPC") server], [informational], [by design],
    [A request credits events sampled after a health test failure, before its reset], [Kernel `esdm_es`], [low], [fixed],
    [A request credits the samples of a failure window before their reset], [Kernel `esdm_es`], [low], [fixed],
    [A blocking read sleeps permanently after a late "not operational"], [Kernel `esdm_cdev`], [medium], [fixed],
    [A read of `/dev/esdm_pr` without memory does not arm the poll back-off], [Kernel `esdm_cdev`], [low], [fixed],
    [A prediction resistant read returns `ERESTARTSYS` without a signal], [Kernel `esdm_cdev`], [low], [fixed],
    [No poll back-off for `/dev/esdm_random` opened with `O_SYNC`], [Kernel `esdm_cdev`], [low], [open],
    [A waiter sleeps next to a free connection for up to one request], [Kernel `esdm_cdev`], [low], [open],
  ),
  caption: [Findings of the model checking],
) <tab:fv-findings>
