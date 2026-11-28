---------------------------- MODULE EsdmKernelEs ----------------------------
(***************************************************************************)
(* The entropy buffer of the kernel module esdm_es: the per-CPU event      *)
(* rings of kernel/esdm_es/esdm_es_ring.[ch], filled by the interrupt and  *)
(* scheduler hooks through esdm_time_process() with the SP800-90B health   *)
(* tests of esdm_health.c, and emptied by the IOCTL reader through         *)
(* esdm_es_drbg_pool_extract() of esdm_es_drbg.c, with the resets of       *)
(* esdm_es_ring_reset() from health test failures, the notifiers and       *)
(* module exit. One step is one atomic variable access or one critical     *)
(* section; the labels name the C functions they come from.                *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - One entropy source: the interrupt and the scheduler source share the  *)
(*   ring code and the health code, each with a ring and health state of   *)
(*   its own. A ring has N slots and holds N-1 events, as the code with    *)
(*   ESDM_DATA_NUM_VALUES. Timing values are left out: a slot holds a      *)
(*   ghost event - whether it is unused, its write parity, and when it was *)
(*   sampled relative to the failures and resets.                          *)
(* - Contexts: an "irq" producer per CPU in IrqCpus runs in hard interrupt *)
(*   context, with interrupts off, and cannot be preempted; a "task"       *)
(*   producer per CPU in TaskCpus is the scheduler hook called from        *)
(*   try_to_wake_up() with preemption disabled, which an interrupt nests   *)
(*   into unless it disables interrupts (SchedIrqOff, the code). The IOCTL *)
(*   reader runs on CPU NC while it holds the ring lock, the notifiers and *)
(*   module exit on CPU 1; elsewhere the reader runs on any CPU. A task    *)
(*   context steps only while no interrupt runs on its CPU.                *)
(* - The health tests: a sample may fail the APT or the RCT (at most       *)
(*   MaxFail times in all) and may end an APT window (MaxWin times), so a  *)
(*   window lasts one sample or more; SB stands for                        *)
(*   ESDM_SP80090B_STARTUP_BLOCKS, and the counter starts at StartBlocks:  *)
(*   SB as in the code, 0 for a startup test passed before, SB + 1 for the *)
(*   window of a failure whose reset is done. A failing sample may be      *)
(*   stored or dropped. The sample fails first and ends the window then,   *)
(*   as the APT does; the RCT failure of a sample that ended a window is   *)
(*   the failure of the CPU's next sample, which is dropped. The stuck     *)
(*   test and the RCT reset of a passing sample only drop samples and are  *)
(*   left out, as are the permanent failure (the same restart), the panic  *)
(*   and the deferred messages.                                            *)
(* - The reader asks for Blocks blocks of Need events each; a block is     *)
(*   credited when it collected Need events, the abstraction of the        *)
(*   oversampling arithmetic. esdm_es_ring_avail_events() is one step: it  *)
(*   only decides whether the request tries. drbg_seed()/drbg_generate()   *)
(*   may fail (SeedFail). NR readers stand for the descriptors of the      *)
(*   device, which the IOCTL mutex serializes (Mutex, the code).           *)
(* - Every context is bounded and ends: a state in which a context waits   *)
(*   and no other can step is a deadlock, which every configuration        *)
(*   checks; Termination states the same as a liveness property.           *)
(* - Not modelled: CPU hotplug (the online mask is all CPUs), the DRBG     *)
(*   registration work, last_timestamp, the timer GCD, the testing         *)
(*   interfaces.                                                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    NC,          \* CPUs
    N,           \* slots of a per-CPU ring
    IrqCpus,     \* CPUs with a producer in hard interrupt context
    TaskCpus,    \* CPUs with a scheduler hook producer in task context
    MaxEv,       \* samples per producer
    Need,        \* events a block needs to be credited
    Blocks,      \* blocks per request
    NR,          \* IOCTL readers: descriptors of the device, other ESDMs
    MaxReq,      \* requests per reader
    Mutex,       \* esdm_cdev_lock serializes the IOCTLs (the code)
    Fips,        \* fips_enabled: health tests and the startup gate
    SB,          \* ESDM_SP80090B_STARTUP_BLOCKS
    StartBlocks, \* sp80090b_startup_blocks at the start
    MaxFail,     \* health test failures
    MaxWin,      \* APT windows completed
    MaxResets,   \* resets by the reboot, PM and vmgenid notifiers
    SeedFail,    \* drbg_seed() or drbg_generate() may fail
    SchedIrqOff, \* esdm_sched_randomness() disables interrupts (the code)
    IrqSave,     \* the ring lock is taken with interrupts off (the code)
    FirstCheck,  \* the startup test is checked before the collection (the
                 \* code)
    FinalCheck,  \* the startup test is checked again before the last
                 \* generation (the code since the fix)
    FinalPend,   \* that check reads the count of changes in progress too
                 \* (the code)
    PendReset,   \* a change of the startup test counts as a reset in progress
                 \* until its reset is done, which fails the startup test (the
                 \* code since the fix)
    PendWin,     \* with PendReset: so does the end of a window, not only a
                 \* failure (the code)
    EarlyReturn, \* with PendWin: but not the end of a window that finds the
                 \* startup test passed (the code)
    FailReset,   \* the first failure of a window resets the rings (the code)
    WinReset,    \* the end of the window of a failure resets them (the code)
    AtomicReset, \* alternative fix, not in the code: such a change and its
                 \* reset are one critical section of the ring lock
    Unload,      \* module exit once the device is closed
    RcuSync      \* exit waits with synchronize_rcu() (the code)

Cpus == 1..NC
Slot == 0..N-1
NoCtx == 0
Cons == 100
ConsProcs == {Cons + 10 * i : i \in 0..NR-1}
Notif == 101
Exit == 102
Prods == IrqCpus \cup {10 + c : c \in TaskCpus}
NotifProcs == IF MaxResets > 0 THEN {Notif} ELSE {}
ExitProcs == IF Unload THEN {Exit} ELSE {}
IsIrq(p) == p \in IrqCpus
CpuOf(p) == IF p < 10 THEN p
            ELSE IF p < Cons THEN p - 10
            ELSE IF p \in ConsProcs THEN NC ELSE 1

Min(a, b) == IF a < b THEN a ELSE b
\* events between the read and the write position, as the code counts them
Dist(w, r) == IF w >= r THEN w - r ELSE N - r + w
Tag0 == [win |-> FALSE, fc |-> 0, rc |-> 0, sv |-> FALSE]

(* --algorithm EsdmKernelEs {
variables
    \* the ring: per-CPU positions, the staging, the lock and generation
    wp = [c \in Cpus |-> 0],
    rp = [c \in Cpus |-> 0],
    rpPend = [c \in Cpus |-> 0],        \* rp_pending
    mask = {},                          \* rp_pending_mask
    gen = 0,
    rpPendGen = 0,                      \* rp_pending_gen
    lock = NoCtx,                       \* ring->lock
    mtx = NoCtx,                        \* esdm_cdev_lock
    \* sp80090b_startup_blocks: APT windows still to pass
    blocks = StartBlocks,
    \* changes of the startup test whose reset is in progress
    pend = 0,
    \* the CPUs: an interrupt runs, a task context disabled interrupts or
    \* preemption
    inIrq = [c \in Cpus |-> FALSE],
    irqOffT = [c \in Cpus |-> FALSE],
    taskOn = [c \in Cpus |-> NoCtx],
    \* the hook registered, the RCU readers in it, the ring arrays freed
    hook = TRUE,
    active = [p \in Prods |-> FALSE],
    freed = FALSE,
    \* ghosts: per slot unused, write parity and the event's tag; the tag
    \* of each producer's sample (sampled in a failure window, failures and
    \* resets before it, a reset while it was in flight) and whether it is
    \* in flight; failures, resets, ends of a window chosen, the startup
    \* test passed once; events stored, credited, and taken out of the
    \* rings - hashed by a block that was released, or discarded by a reset
    fr = [c \in Cpus |-> [i \in Slot |-> FALSE]],
    ver = [c \in Cpus |-> [i \in Slot |-> 0]],
    tg = [c \in Cpus |-> [i \in Slot |-> Tag0]],
    tagE = [p \in Prods |-> Tag0],
    infl = [p \in Prods |-> FALSE],
    fcnt = 0,
    rcnt = 0,
    wins = 0,
    passed = StartBlocks = 0,
    produced = 0,
    credited = 0,
    gone = 0,
    viol = {};

define {
    \* a task context steps only while no interrupt runs on its CPU
    Run(p) == IsIrq(p) \/ ~inIrq[CpuOf(p)]
    \* slot i holds an event not consumed: between rp and wp
    InRing(c, i) == Dist(i, rp[c]) < Dist(wp[c], rp[c])
    RECURSIVE SumAvail(_)
    SumAvail(S) == IF S = {} THEN 0
                   ELSE LET c == CHOOSE c \in S : TRUE
                        IN Dist(wp[c], rp[c]) + SumAvail(S \ {c})
    \* what a block takes from the slots it hashed: slots handed out or
    \* discarded before, slots overwritten since the collection, events of
    \* the window of a failure
    Bad(S) ==
        LET T(e) == tg[e[1]][e[2]]
            F == {e \in S : fr[e[1]][e[2]]}
        IN  (IF \E e \in S : ~fr[e[1]][e[2]] THEN {"Stale"} ELSE {})
            \cup (IF \E e \in S : ver[e[1]][e[2]] # e[3]
                  THEN {"Overwritten"} ELSE {})
            \cup (IF \E e \in F : T(e).win /\ ~T(e).sv
                  THEN {"Window"} ELSE {})
            \cup (IF \E e \in F : T(e).win THEN {"WindowSurv"} ELSE {})
    \* when the events a block hashed were sampled
    Tags(S) ==
        {[fc |-> tg[e[1]][e[2]].fc, rc |-> tg[e[1]][e[2]].rc,
          sv |-> tg[e[1]][e[2]].sv] : e \in {x \in S : fr[x[1]][x[2]]}}
    \* what a request credits of events sampled before the last of fs
    \* failures or of rs resets
    Old(H, fs, rs) ==
        (IF \E t \in H : t.fc < fs /\ ~t.sv THEN {"PreFail"} ELSE {})
        \cup (IF \E t \in H : t.fc < fs THEN {"PreFailSurv"} ELSE {})
        \cup (IF \E t \in H : t.rc < rs /\ ~t.sv THEN {"PreReset"} ELSE {})
        \cup (IF \E t \in H : t.rc < rs THEN {"PreResetSurv"} ELSE {})
}

\* raw_spin_lock_irqsave(&ring->lock): a task context disables interrupts
\* and preemption on its CPU
macro acq() {
    await lock = NoCtx /\ Run(self)
          /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self});
    lock := self;
    if (~IsIrq(self)) {
        if (IrqSave) irqOffT[CpuOf(self)] := TRUE;
        taskOn[CpuOf(self)] := self;
    };
}

\* raw_spin_unlock_irqrestore(), back to the state before the lock
macro rel() {
    lock := NoCtx;
    if (~IsIrq(self)) {
        irqOffT[CpuOf(self)] := self \in Prods /\ SchedIrqOff;
        taskOn[CpuOf(self)] := IF self \in Prods THEN self ELSE NoCtx;
    };
}

\* esdm_es_ring_reset(): rp moves up to wp on every CPU, the generation
\* changes; a sample in flight is stored after it
macro resetBody() {
    gen := gen + 1;
    rcnt := rcnt + 1;
    gone := gone + SumAvail(Cpus);
    fr := [c \in Cpus |-> [i \in Slot |-> fr[c][i] /\ ~InRing(c, i)]];
    rp := wp;
    tagE := [q \in Prods |-> IF infl[q] THEN [tagE[q] EXCEPT !.sv = TRUE]
                             ELSE tagE[q]];
}

\* esdm_es_ring_reset(); with AtomicReset, xc names the update of the
\* startup test that comes with it in the same critical section: "fail"
\* the exchange of esdm_sp80090b_startup_restart(), resetting only for the
\* window's first failure, "win" the decrement of esdm_sp80090b_startup(),
\* resetting only when the window of a failure completed
procedure ringReset(xc)
{
rr1: acq();
rr2: await Run(self);
     if (xc = "fail") {
         with (o = blocks) {
             fcnt := fcnt + 1;
             blocks := SB + 1;
             if (o # SB + 1 /\ FailReset) resetBody();
         };
     } else if (xc = "win") {
         with (o = blocks) {
             if (o > 0) blocks := o - 1;
             if (o = 1) passed := TRUE;
             if (o - 1 = SB /\ WinReset) resetBody();
         };
     } else {
         resetBody();
     };
     rel();
     return;
}

\* the interrupt hook esdm_add_interrupt_randomness(), or the scheduler
\* hook esdm_sched_randomness(), each running esdm_time_process()
fair process (p \in Prods)
    variables n = 0, w = 0, r = 0, old = 0, res = -1, fl = FALSE,
              we = FALSE, st = TRUE, fno = 0, wfc = 0;
{
pe0: while (n < MaxEv) {
         \* the hook fires, an RCU read-side critical section
         if (IsIrq(self)) {
             await ~inIrq[CpuOf(self)] /\ ~irqOffT[CpuOf(self)];
             inIrq[CpuOf(self)] := TRUE;
         } else {
             await ~inIrq[CpuOf(self)] /\ taskOn[CpuOf(self)] = NoCtx;
             taskOn[CpuOf(self)] := self;
             irqOffT[CpuOf(self)] := SchedIrqOff;
         };
         n := n + 1;
         active[self] := TRUE;
         if (~hook) {
             goto pe9;
         } else {
             \* random_get_entropy(): the sample is taken
             tagE[self] := [win |-> blocks = SB + 1, fc |-> fcnt,
                            rc |-> rcnt, sv |-> FALSE];
             infl[self] := TRUE;
         };
         \* esdm_apt_insert() / esdm_rct(): a failure restarts the startup
         \* test, esdm_sp80090b_startup_restart(). Before the fix, the
         \* exchange is its first step.
ht0:     await Run(self);
         either {
             skip;
         } or {
             await Fips /\ fcnt < MaxFail;
             fl := TRUE;
             if (AtomicReset) {
                 call ringReset("fail");
                 goto ht2;
             } else if (PendReset) {
                 \* esdm_sp80090b_change_begin()
                 pend := pend + 1;
                 goto hp0;
             } else {
                 old := blocks;
                 blocks := SB + 1;
                 fcnt := fcnt + 1;
                 fno := fcnt;
             };
         };
ht1:     await Run(self);
         if (fl /\ old # SB + 1 /\ FailReset) call ringReset("none");
         \* the sample ends an APT window: esdm_sp80090b_startup(). With
         \* the fix, the read of the counter is the step: the startup test
         \* passed, nothing to change and no change in progress.
ht2:     await Run(self);
         either {
             skip;
         } or {
             await Fips /\ wins < MaxWin;
             wins := wins + 1;
             we := TRUE;
             if (AtomicReset) {
                 call ringReset("win");
                 goto ra1;
             } else if (PendReset /\ PendWin) {
                 if (EarlyReturn /\ blocks = 0) goto ra1 else goto hp2;
             } else {
                 res := blocks - 1;
                 if (blocks > 0) blocks := blocks - 1;
                 if (blocks = 0) passed := TRUE;
                 wfc := fcnt;
             };
         };
ht3:     await Run(self);
         if (we /\ res = SB /\ WinReset) call ringReset("none");
         \* esdm_es_ring_add(): load wp and rp; a failing sample may be
         \* dropped
ra1:     await Run(self);
         w := wp[CpuOf(self)];
         r := rp[CpuOf(self)];
         either st := TRUE or { await fl; st := FALSE };
         \* the full check, the slot and wp
ra2:     await Run(self);
         if (st /\ (w + 1) % N # r) {
             viol := viol
                 \cup (IF InRing(CpuOf(self), w) THEN {"Overrun"} ELSE {})
                 \cup (IF freed THEN {"UseAfterFree"} ELSE {});
             fr[CpuOf(self)][w] := TRUE;
             ver[CpuOf(self)][w] := 1 - ver[CpuOf(self)][w];
             tg[CpuOf(self)][w] := tagE[self];
             wp[CpuOf(self)] := (w + 1) % N;
             produced := produced + 1;
         };
         \* the hook returns
pe9:     await Run(self);
         active[self] := FALSE;
         infl[self] := FALSE;
         if (IsIrq(self)) {
             inIrq[CpuOf(self)] := FALSE;
         } else {
             taskOn[CpuOf(self)] := NoCtx;
             irqOffT[CpuOf(self)] := FALSE;
         };
         w := 0;
         r := 0;
         old := 0;
         res := -1;
         fl := FALSE;
         we := FALSE;
         st := TRUE;
         fno := 0;
         wfc := 0;
         goto pe0;
         \* with PendReset: the exchange, and the reset for the first
         \* failure of a window
hp0:     await Run(self);
         old := blocks;
         blocks := SB + 1;
         fcnt := fcnt + 1;
         fno := fcnt;
         if (old # SB + 1 /\ FailReset) {
             call ringReset("none");
             goto hp1;
         } else {
             goto hp1;
         };
         \* esdm_sp80090b_change_end()
hp1:     await Run(self);
         pend := pend - 1;
         goto ht2;
         \* ... the end of a window: esdm_sp80090b_change_begin(),
hp2:     await Run(self);
         pend := pend + 1;
         \* the decrement, and the reset when the window of a failure
         \* completed,
hp3:     await Run(self);
         res := blocks - 1;
         if (blocks > 0) blocks := blocks - 1;
         if (blocks = 0) passed := TRUE;
         wfc := fcnt;
         if (res = SB /\ WinReset) {
             call ringReset("none");
             goto hp4;
         } else {
             goto hp4;
         };
         \* esdm_sp80090b_change_end()
hp4:     await Run(self);
         pend := pend - 1;
         goto ra1;
     };
}

\* esdm_cdev_ioctl() of ESDM_IRQ_ENT_BUF / ESDM_SCHED_ENT_BUF under
\* esdm_cdev_lock: esdm_es_drbg_pool_extract()
fair process (cs \in ConsProcs)
    variables nr = 0, g = 0, fseen = 0, b = 0, coll = 0, ci = 1,
              wpos = 0, staged = {}, ok = FALSE, valid = FALSE, rbad = {},
              htag = {};
{
c0: while (nr < MaxReq) {
        \* esdm_cdev_ioctl(): mutex_lock(&esdm_cdev_lock)
        if (Mutex) await mtx = NoCtx;
        mtx := IF Mutex THEN self ELSE NoCtx;
        nr := nr + 1;
        \* esdm_es_ring_gen(), before the startup test
c1:     acq();
c2:     await Run(self);
        g := gen;
        rel();
        \* esdm_sp80090b_startup_complete_es()
c3:     if (FirstCheck /\ Fips /\ blocks # 0) {
            goto c9;
        } else if (FirstCheck /\ Fips /\ PendReset) {
            goto c3p;
        } else {
            fseen := fcnt;
        };
        \* esdm_es_drbg_avail_entropy()
c4:     if (SumAvail(Cpus) < Blocks * Need) goto c9;
cb:     while (b < Blocks) {
            \* esdm_es_ring_collect(): the generation of the staging
cl0:        acq();
cl1:        await Run(self);
            rpPendGen := gen;
            rel();
            \* per CPU: wp, then rp, then the staging
cl2:        while (ci <= NC /\ coll < Need) {
                wpos := wp[ci];
cl3:            with (rpos = rp[ci],
                      u = Min(Need - coll, Min(Dist(wpos, rpos), N))) {
                    if (u > 0) {
                        staged := staged \cup
                            {<<ci, (rpos + j) % N, ver[ci][(rpos + j) % N]>> :
                             j \in 0..u-1};
                        rpPend[ci] := (rpos + u) % N;
                        mask := mask \cup {ci};
                        coll := coll + u;
                    };
                    ci := ci + 1;
                };
            };
            \* too few: esdm_es_ring_discard(), the events stay
cl4:        if (coll < Need) {
                mask := {};
                goto c9;
            };
            \* drbg_seed() hashes the staged slots, drbg_generate()
hs1:        either {
                ok := TRUE;
                rbad := rbad \cup Bad(staged);
                htag := htag \cup Tags(staged);
            } or {
                await SeedFail;
                ok := FALSE;
            };
            \* esdm_es_ring_release(): publish only without a reset since
rl0:        acq();
rl1:        await Run(self);
            valid := gen = rpPendGen;
            if (gen = rpPendGen) {
                gone := gone + Cardinality(staged);
                fr := [c \in Cpus |->
                       [i \in Slot |->
                        fr[c][i]
                        /\ ~(c \in mask
                             /\ Dist(i, rp[c]) < Dist(rpPend[c], rp[c]))]];
                rp := [c \in Cpus |-> IF c \in mask THEN rpPend[c] ELSE rp[c]];
            };
            rel();
rl2:        mask := {};
            if (~(valid /\ ok)) {
                goto c9;
            } else {
                b := b + 1;
                coll := 0;
                ci := 1;
                staged := {};
                valid := FALSE;
                ok := FALSE;
            };
        };
        \* the fix: the startup test once more, before the generation
cf0:    if (FinalCheck /\ Fips /\ blocks # 0) {
            goto c9;
        } else if (FinalCheck /\ Fips /\ PendReset /\ FinalPend) {
            fseen := fcnt;
            goto cfp;
        } else if (FinalCheck) {
            fseen := fcnt;
        };
        \* the generation across the whole request; the ghost: what the
        \* request credits, against the failures before its last startup
        \* check and the resets up to now
cf1:    acq();
cf2:    await Run(self);
        if (gen = g) {
            viol := viol \cup rbad \cup Old(htag, fseen, rcnt);
            credited := credited + Blocks * Need;
        };
        rel();
c9:     mtx := NoCtx;
        b := 0;
        coll := 0;
        ci := 1;
        wpos := 0;
        staged := {};
        ok := FALSE;
        valid := FALSE;
        rbad := {};
        htag := {};
        g := 0;
        fseen := 0;
        goto c0;
        \* with PendReset: no reset in progress either, read after the counter
c3p:    if (pend # 0) {
            goto c9;
        } else {
            fseen := fcnt;
            goto c4;
        };
cfp:    if (pend # 0) goto c9 else goto cf1;
    };
}

\* the reboot, PM and vmgenid notifiers: esdm_es_mgr_irq_reset()
fair process (nt \in NotifProcs)
    variables k = 0;
{
nf0: while (k < MaxResets) {
         k := k + 1;
         call ringReset("none");
     };
}

\* esdm_es_irq_module_exit() once the device is closed: unregister the
\* hook, synchronize_rcu(), free the arrays
fair process (ex \in ExitProcs)
{
ex0: await \A q \in ConsProcs : pc[q] = "Done";
     hook := FALSE;
ex1: if (RcuSync) await \A q \in Prods : ~active[q];
ex2: freed := TRUE;
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, blocks, pend, 
          inIrq, irqOffT, taskOn, hook, active, freed, fr, ver, tg, tagE, 
          infl, fcnt, rcnt, wins, passed, produced, credited, gone, viol, pc, 
          stack

(* define statement *)
Run(p) == IsIrq(p) \/ ~inIrq[CpuOf(p)]

InRing(c, i) == Dist(i, rp[c]) < Dist(wp[c], rp[c])
RECURSIVE SumAvail(_)
SumAvail(S) == IF S = {} THEN 0
               ELSE LET c == CHOOSE c \in S : TRUE
                    IN Dist(wp[c], rp[c]) + SumAvail(S \ {c})



Bad(S) ==
    LET T(e) == tg[e[1]][e[2]]
        F == {e \in S : fr[e[1]][e[2]]}
    IN  (IF \E e \in S : ~fr[e[1]][e[2]] THEN {"Stale"} ELSE {})
        \cup (IF \E e \in S : ver[e[1]][e[2]] # e[3]
              THEN {"Overwritten"} ELSE {})
        \cup (IF \E e \in F : T(e).win /\ ~T(e).sv
              THEN {"Window"} ELSE {})
        \cup (IF \E e \in F : T(e).win THEN {"WindowSurv"} ELSE {})

Tags(S) ==
    {[fc |-> tg[e[1]][e[2]].fc, rc |-> tg[e[1]][e[2]].rc,
      sv |-> tg[e[1]][e[2]].sv] : e \in {x \in S : fr[x[1]][x[2]]}}


Old(H, fs, rs) ==
    (IF \E t \in H : t.fc < fs /\ ~t.sv THEN {"PreFail"} ELSE {})
    \cup (IF \E t \in H : t.fc < fs THEN {"PreFailSurv"} ELSE {})
    \cup (IF \E t \in H : t.rc < rs /\ ~t.sv THEN {"PreReset"} ELSE {})
    \cup (IF \E t \in H : t.rc < rs THEN {"PreResetSurv"} ELSE {})

VARIABLES xc, n, w, r, old, res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
          ci, wpos, staged, ok, valid, rbad, htag, k

vars == << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, blocks, pend, 
           inIrq, irqOffT, taskOn, hook, active, freed, fr, ver, tg, tagE, 
           infl, fcnt, rcnt, wins, passed, produced, credited, gone, viol, pc, 
           stack, xc, n, w, r, old, res, fl, we, st, fno, wfc, nr, g, fseen, 
           b, coll, ci, wpos, staged, ok, valid, rbad, htag, k >>

ProcSet == (Prods) \cup (ConsProcs) \cup (NotifProcs) \cup (ExitProcs)

Init == (* Global variables *)
        /\ wp = [c \in Cpus |-> 0]
        /\ rp = [c \in Cpus |-> 0]
        /\ rpPend = [c \in Cpus |-> 0]
        /\ mask = {}
        /\ gen = 0
        /\ rpPendGen = 0
        /\ lock = NoCtx
        /\ mtx = NoCtx
        /\ blocks = StartBlocks
        /\ pend = 0
        /\ inIrq = [c \in Cpus |-> FALSE]
        /\ irqOffT = [c \in Cpus |-> FALSE]
        /\ taskOn = [c \in Cpus |-> NoCtx]
        /\ hook = TRUE
        /\ active = [p \in Prods |-> FALSE]
        /\ freed = FALSE
        /\ fr = [c \in Cpus |-> [i \in Slot |-> FALSE]]
        /\ ver = [c \in Cpus |-> [i \in Slot |-> 0]]
        /\ tg = [c \in Cpus |-> [i \in Slot |-> Tag0]]
        /\ tagE = [p \in Prods |-> Tag0]
        /\ infl = [p \in Prods |-> FALSE]
        /\ fcnt = 0
        /\ rcnt = 0
        /\ wins = 0
        /\ passed = (StartBlocks = 0)
        /\ produced = 0
        /\ credited = 0
        /\ gone = 0
        /\ viol = {}
        (* Procedure ringReset *)
        /\ xc = [ self \in ProcSet |-> defaultInitValue]
        (* Process p *)
        /\ n = [self \in Prods |-> 0]
        /\ w = [self \in Prods |-> 0]
        /\ r = [self \in Prods |-> 0]
        /\ old = [self \in Prods |-> 0]
        /\ res = [self \in Prods |-> -1]
        /\ fl = [self \in Prods |-> FALSE]
        /\ we = [self \in Prods |-> FALSE]
        /\ st = [self \in Prods |-> TRUE]
        /\ fno = [self \in Prods |-> 0]
        /\ wfc = [self \in Prods |-> 0]
        (* Process cs *)
        /\ nr = [self \in ConsProcs |-> 0]
        /\ g = [self \in ConsProcs |-> 0]
        /\ fseen = [self \in ConsProcs |-> 0]
        /\ b = [self \in ConsProcs |-> 0]
        /\ coll = [self \in ConsProcs |-> 0]
        /\ ci = [self \in ConsProcs |-> 1]
        /\ wpos = [self \in ConsProcs |-> 0]
        /\ staged = [self \in ConsProcs |-> {}]
        /\ ok = [self \in ConsProcs |-> FALSE]
        /\ valid = [self \in ConsProcs |-> FALSE]
        /\ rbad = [self \in ConsProcs |-> {}]
        /\ htag = [self \in ConsProcs |-> {}]
        (* Process nt *)
        /\ k = [self \in NotifProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Prods -> "pe0"
                                        [] self \in ConsProcs -> "c0"
                                        [] self \in NotifProcs -> "nf0"
                                        [] self \in ExitProcs -> "ex0"]

rr1(self) == /\ pc[self] = "rr1"
             /\ lock = NoCtx /\ Run(self)
                /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self})
             /\ lock' = self
             /\ IF ~IsIrq(self)
                   THEN /\ IF IrqSave
                              THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = TRUE]
                              ELSE /\ TRUE
                                   /\ UNCHANGED irqOffT
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "rr2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, fr, ver, tg, 
                             tagE, infl, fcnt, rcnt, wins, passed, produced, 
                             credited, gone, viol, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

rr2(self) == /\ pc[self] = "rr2"
             /\ Run(self)
             /\ IF xc[self] = "fail"
                   THEN /\ LET o == blocks IN
                             /\ fcnt' = fcnt + 1
                             /\ blocks' = SB + 1
                             /\ IF o # SB + 1 /\ FailReset
                                   THEN /\ gen' = gen + 1
                                        /\ rcnt' = rcnt + 1
                                        /\ gone' = gone + SumAvail(Cpus)
                                        /\ fr' = [c \in Cpus |-> [i \in Slot |-> fr[c][i] /\ ~InRing(c, i)]]
                                        /\ rp' = wp
                                        /\ tagE' = [q \in Prods |-> IF infl[q] THEN [tagE[q] EXCEPT !.sv = TRUE]
                                                                    ELSE tagE[q]]
                                   ELSE /\ TRUE
                                        /\ UNCHANGED << rp, gen, fr, tagE, 
                                                        rcnt, gone >>
                        /\ UNCHANGED passed
                   ELSE /\ IF xc[self] = "win"
                              THEN /\ LET o == blocks IN
                                        /\ IF o > 0
                                              THEN /\ blocks' = o - 1
                                              ELSE /\ TRUE
                                                   /\ UNCHANGED blocks
                                        /\ IF o = 1
                                              THEN /\ passed' = TRUE
                                              ELSE /\ TRUE
                                                   /\ UNCHANGED passed
                                        /\ IF o - 1 = SB /\ WinReset
                                              THEN /\ gen' = gen + 1
                                                   /\ rcnt' = rcnt + 1
                                                   /\ gone' = gone + SumAvail(Cpus)
                                                   /\ fr' = [c \in Cpus |-> [i \in Slot |-> fr[c][i] /\ ~InRing(c, i)]]
                                                   /\ rp' = wp
                                                   /\ tagE' = [q \in Prods |-> IF infl[q] THEN [tagE[q] EXCEPT !.sv = TRUE]
                                                                               ELSE tagE[q]]
                                              ELSE /\ TRUE
                                                   /\ UNCHANGED << rp, gen, fr, 
                                                                   tagE, rcnt, 
                                                                   gone >>
                              ELSE /\ gen' = gen + 1
                                   /\ rcnt' = rcnt + 1
                                   /\ gone' = gone + SumAvail(Cpus)
                                   /\ fr' = [c \in Cpus |-> [i \in Slot |-> fr[c][i] /\ ~InRing(c, i)]]
                                   /\ rp' = wp
                                   /\ tagE' = [q \in Prods |-> IF infl[q] THEN [tagE[q] EXCEPT !.sv = TRUE]
                                                               ELSE tagE[q]]
                                   /\ UNCHANGED << blocks, passed >>
                        /\ fcnt' = fcnt
             /\ lock' = NoCtx
             /\ IF ~IsIrq(self)
                   THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = self \in Prods /\ SchedIrqOff]
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = IF self \in Prods THEN self ELSE NoCtx]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ xc' = [xc EXCEPT ![self] = Head(stack[self]).xc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << wp, rpPend, mask, rpPendGen, mtx, pend, inIrq, 
                             hook, active, freed, ver, tg, infl, wins, 
                             produced, credited, viol, n, w, r, old, res, fl, 
                             we, st, fno, wfc, nr, g, fseen, b, coll, ci, wpos, 
                             staged, ok, valid, rbad, htag, k >>

ringReset(self) == rr1(self) \/ rr2(self)

pe0(self) == /\ pc[self] = "pe0"
             /\ IF n[self] < MaxEv
                   THEN /\ IF IsIrq(self)
                              THEN /\ ~inIrq[CpuOf(self)] /\ ~irqOffT[CpuOf(self)]
                                   /\ inIrq' = [inIrq EXCEPT ![CpuOf(self)] = TRUE]
                                   /\ UNCHANGED << irqOffT, taskOn >>
                              ELSE /\ ~inIrq[CpuOf(self)] /\ taskOn[CpuOf(self)] = NoCtx
                                   /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                                   /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = SchedIrqOff]
                                   /\ inIrq' = inIrq
                        /\ n' = [n EXCEPT ![self] = n[self] + 1]
                        /\ active' = [active EXCEPT ![self] = TRUE]
                        /\ IF ~hook
                              THEN /\ pc' = [pc EXCEPT ![self] = "pe9"]
                                   /\ UNCHANGED << tagE, infl >>
                              ELSE /\ tagE' = [tagE EXCEPT ![self] = [win |-> blocks = SB + 1, fc |-> fcnt,
                                                                      rc |-> rcnt, sv |-> FALSE]]
                                   /\ infl' = [infl EXCEPT ![self] = TRUE]
                                   /\ pc' = [pc EXCEPT ![self] = "ht0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << inIrq, irqOffT, taskOn, active, tagE, 
                                        infl, n >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, hook, freed, fr, ver, tg, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, w, r, old, res, fl, we, st, fno, 
                             wfc, nr, g, fseen, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

ht0(self) == /\ pc[self] = "ht0"
             /\ Run(self)
             /\ \/ /\ TRUE
                   /\ pc' = [pc EXCEPT ![self] = "ht1"]
                   /\ UNCHANGED <<blocks, pend, fcnt, stack, xc, old, fl, fno>>
                \/ /\ Fips /\ fcnt < MaxFail
                   /\ fl' = [fl EXCEPT ![self] = TRUE]
                   /\ IF AtomicReset
                         THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                          pc        |->  "ht2",
                                                                          xc        |->  xc[self] ] >>
                                                                      \o stack[self]]
                                 /\ xc' = [xc EXCEPT ![self] = "fail"]
                              /\ pc' = [pc EXCEPT ![self] = "rr1"]
                              /\ UNCHANGED << blocks, pend, fcnt, old, fno >>
                         ELSE /\ IF PendReset
                                    THEN /\ pend' = pend + 1
                                         /\ pc' = [pc EXCEPT ![self] = "hp0"]
                                         /\ UNCHANGED << blocks, fcnt, old, 
                                                         fno >>
                                    ELSE /\ old' = [old EXCEPT ![self] = blocks]
                                         /\ blocks' = SB + 1
                                         /\ fcnt' = fcnt + 1
                                         /\ fno' = [fno EXCEPT ![self] = fcnt']
                                         /\ pc' = [pc EXCEPT ![self] = "ht1"]
                                         /\ pend' = pend
                              /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             inIrq, irqOffT, taskOn, hook, active, freed, fr, 
                             ver, tg, tagE, infl, rcnt, wins, passed, produced, 
                             credited, gone, viol, n, w, r, res, we, st, wfc, 
                             nr, g, fseen, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

ht1(self) == /\ pc[self] = "ht1"
             /\ Run(self)
             /\ IF fl[self] /\ old[self] # SB + 1 /\ FailReset
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                    pc        |->  "ht2",
                                                                    xc        |->  xc[self] ] >>
                                                                \o stack[self]]
                           /\ xc' = [xc EXCEPT ![self] = "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ht2"]
                        /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, n, w, r, old, res, fl, we, st, fno, wfc, nr, 
                             g, fseen, b, coll, ci, wpos, staged, ok, valid, 
                             rbad, htag, k >>

ht2(self) == /\ pc[self] = "ht2"
             /\ Run(self)
             /\ \/ /\ TRUE
                   /\ pc' = [pc EXCEPT ![self] = "ht3"]
                   /\ UNCHANGED <<blocks, wins, passed, stack, xc, res, we, wfc>>
                \/ /\ Fips /\ wins < MaxWin
                   /\ wins' = wins + 1
                   /\ we' = [we EXCEPT ![self] = TRUE]
                   /\ IF AtomicReset
                         THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                          pc        |->  "ra1",
                                                                          xc        |->  xc[self] ] >>
                                                                      \o stack[self]]
                                 /\ xc' = [xc EXCEPT ![self] = "win"]
                              /\ pc' = [pc EXCEPT ![self] = "rr1"]
                              /\ UNCHANGED << blocks, passed, res, wfc >>
                         ELSE /\ IF PendReset /\ PendWin
                                    THEN /\ IF EarlyReturn /\ blocks = 0
                                               THEN /\ pc' = [pc EXCEPT ![self] = "ra1"]
                                               ELSE /\ pc' = [pc EXCEPT ![self] = "hp2"]
                                         /\ UNCHANGED << blocks, passed, res, 
                                                         wfc >>
                                    ELSE /\ res' = [res EXCEPT ![self] = blocks - 1]
                                         /\ IF blocks > 0
                                               THEN /\ blocks' = blocks - 1
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED blocks
                                         /\ IF blocks' = 0
                                               THEN /\ passed' = TRUE
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED passed
                                         /\ wfc' = [wfc EXCEPT ![self] = fcnt]
                                         /\ pc' = [pc EXCEPT ![self] = "ht3"]
                              /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                             fr, ver, tg, tagE, infl, fcnt, rcnt, produced, 
                             credited, gone, viol, n, w, r, old, fl, st, fno, 
                             nr, g, fseen, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

ht3(self) == /\ pc[self] = "ht3"
             /\ Run(self)
             /\ IF we[self] /\ res[self] = SB /\ WinReset
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                    pc        |->  "ra1",
                                                                    xc        |->  xc[self] ] >>
                                                                \o stack[self]]
                           /\ xc' = [xc EXCEPT ![self] = "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ra1"]
                        /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, n, w, r, old, res, fl, we, st, fno, wfc, nr, 
                             g, fseen, b, coll, ci, wpos, staged, ok, valid, 
                             rbad, htag, k >>

ra1(self) == /\ pc[self] = "ra1"
             /\ Run(self)
             /\ w' = [w EXCEPT ![self] = wp[CpuOf(self)]]
             /\ r' = [r EXCEPT ![self] = rp[CpuOf(self)]]
             /\ \/ /\ st' = [st EXCEPT ![self] = TRUE]
                \/ /\ fl[self]
                   /\ st' = [st EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "ra2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, old, res, fl, we, fno, wfc, 
                             nr, g, fseen, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

ra2(self) == /\ pc[self] = "ra2"
             /\ Run(self)
             /\ IF st[self] /\ (w[self] + 1) % N # r[self]
                   THEN /\ viol' =     viol
                                   \cup (IF InRing(CpuOf(self), w[self]) THEN {"Overrun"} ELSE {})
                                   \cup (IF freed THEN {"UseAfterFree"} ELSE {})
                        /\ fr' = [fr EXCEPT ![CpuOf(self)][w[self]] = TRUE]
                        /\ ver' = [ver EXCEPT ![CpuOf(self)][w[self]] = 1 - ver[CpuOf(self)][w[self]]]
                        /\ tg' = [tg EXCEPT ![CpuOf(self)][w[self]] = tagE[self]]
                        /\ wp' = [wp EXCEPT ![CpuOf(self)] = (w[self] + 1) % N]
                        /\ produced' = produced + 1
                   ELSE /\ TRUE
                        /\ UNCHANGED << wp, fr, ver, tg, produced, viol >>
             /\ pc' = [pc EXCEPT ![self] = "pe9"]
             /\ UNCHANGED << rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, tagE, infl, fcnt, rcnt, wins, 
                             passed, credited, gone, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

pe9(self) == /\ pc[self] = "pe9"
             /\ Run(self)
             /\ active' = [active EXCEPT ![self] = FALSE]
             /\ infl' = [infl EXCEPT ![self] = FALSE]
             /\ IF IsIrq(self)
                   THEN /\ inIrq' = [inIrq EXCEPT ![CpuOf(self)] = FALSE]
                        /\ UNCHANGED << irqOffT, taskOn >>
                   ELSE /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = NoCtx]
                        /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = FALSE]
                        /\ inIrq' = inIrq
             /\ w' = [w EXCEPT ![self] = 0]
             /\ r' = [r EXCEPT ![self] = 0]
             /\ old' = [old EXCEPT ![self] = 0]
             /\ res' = [res EXCEPT ![self] = -1]
             /\ fl' = [fl EXCEPT ![self] = FALSE]
             /\ we' = [we EXCEPT ![self] = FALSE]
             /\ st' = [st EXCEPT ![self] = TRUE]
             /\ fno' = [fno EXCEPT ![self] = 0]
             /\ wfc' = [wfc EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "pe0"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, hook, freed, fr, ver, tg, tagE, 
                             fcnt, rcnt, wins, passed, produced, credited, 
                             gone, viol, stack, xc, n, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

hp0(self) == /\ pc[self] = "hp0"
             /\ Run(self)
             /\ old' = [old EXCEPT ![self] = blocks]
             /\ blocks' = SB + 1
             /\ fcnt' = fcnt + 1
             /\ fno' = [fno EXCEPT ![self] = fcnt']
             /\ IF old'[self] # SB + 1 /\ FailReset
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                    pc        |->  "hp1",
                                                                    xc        |->  xc[self] ] >>
                                                                \o stack[self]]
                           /\ xc' = [xc EXCEPT ![self] = "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hp1"]
                        /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                             fr, ver, tg, tagE, infl, rcnt, wins, passed, 
                             produced, credited, gone, viol, n, w, r, res, fl, 
                             we, st, wfc, nr, g, fseen, b, coll, ci, wpos, 
                             staged, ok, valid, rbad, htag, k >>

hp1(self) == /\ pc[self] = "hp1"
             /\ Run(self)
             /\ pend' = pend - 1
             /\ pc' = [pc EXCEPT ![self] = "ht2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, inIrq, irqOffT, taskOn, hook, active, 
                             freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             passed, produced, credited, gone, viol, stack, xc, 
                             n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                             fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                             htag, k >>

hp2(self) == /\ pc[self] = "hp2"
             /\ Run(self)
             /\ pend' = pend + 1
             /\ pc' = [pc EXCEPT ![self] = "hp3"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, inIrq, irqOffT, taskOn, hook, active, 
                             freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             passed, produced, credited, gone, viol, stack, xc, 
                             n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                             fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                             htag, k >>

hp3(self) == /\ pc[self] = "hp3"
             /\ Run(self)
             /\ res' = [res EXCEPT ![self] = blocks - 1]
             /\ IF blocks > 0
                   THEN /\ blocks' = blocks - 1
                   ELSE /\ TRUE
                        /\ UNCHANGED blocks
             /\ IF blocks' = 0
                   THEN /\ passed' = TRUE
                   ELSE /\ TRUE
                        /\ UNCHANGED passed
             /\ wfc' = [wfc EXCEPT ![self] = fcnt]
             /\ IF res'[self] = SB /\ WinReset
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                    pc        |->  "hp4",
                                                                    xc        |->  xc[self] ] >>
                                                                \o stack[self]]
                           /\ xc' = [xc EXCEPT ![self] = "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hp4"]
                        /\ UNCHANGED << stack, xc >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                             fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             produced, credited, gone, viol, n, w, r, old, fl, 
                             we, st, fno, nr, g, fseen, b, coll, ci, wpos, 
                             staged, ok, valid, rbad, htag, k >>

hp4(self) == /\ pc[self] = "hp4"
             /\ Run(self)
             /\ pend' = pend - 1
             /\ pc' = [pc EXCEPT ![self] = "ra1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, inIrq, irqOffT, taskOn, hook, active, 
                             freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             passed, produced, credited, gone, viol, stack, xc, 
                             n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                             fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                             htag, k >>

p(self) == pe0(self) \/ ht0(self) \/ ht1(self) \/ ht2(self) \/ ht3(self)
              \/ ra1(self) \/ ra2(self) \/ pe9(self) \/ hp0(self)
              \/ hp1(self) \/ hp2(self) \/ hp3(self) \/ hp4(self)

c0(self) == /\ pc[self] = "c0"
            /\ IF nr[self] < MaxReq
                  THEN /\ IF Mutex
                             THEN /\ mtx = NoCtx
                             ELSE /\ TRUE
                       /\ mtx' = IF Mutex THEN self ELSE NoCtx
                       /\ nr' = [nr EXCEPT ![self] = nr[self] + 1]
                       /\ pc' = [pc EXCEPT ![self] = "c1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ UNCHANGED << mtx, nr >>
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, blocks, 
                            pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                            fr, ver, tg, tagE, infl, fcnt, rcnt, wins, passed, 
                            produced, credited, gone, viol, stack, xc, n, w, r, 
                            old, res, fl, we, st, fno, wfc, g, fseen, b, coll, 
                            ci, wpos, staged, ok, valid, rbad, htag, k >>

c1(self) == /\ pc[self] = "c1"
            /\ lock = NoCtx /\ Run(self)
               /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self})
            /\ lock' = self
            /\ IF ~IsIrq(self)
                  THEN /\ IF IrqSave
                             THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = TRUE]
                             ELSE /\ TRUE
                                  /\ UNCHANGED irqOffT
                       /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                  ELSE /\ TRUE
                       /\ UNCHANGED << irqOffT, taskOn >>
            /\ pc' = [pc EXCEPT ![self] = "c2"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                            pend, inIrq, hook, active, freed, fr, ver, tg, 
                            tagE, infl, fcnt, rcnt, wins, passed, produced, 
                            credited, gone, viol, stack, xc, n, w, r, old, res, 
                            fl, we, st, fno, wfc, nr, g, fseen, b, coll, ci, 
                            wpos, staged, ok, valid, rbad, htag, k >>

c2(self) == /\ pc[self] = "c2"
            /\ Run(self)
            /\ g' = [g EXCEPT ![self] = gen]
            /\ lock' = NoCtx
            /\ IF ~IsIrq(self)
                  THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = self \in Prods /\ SchedIrqOff]
                       /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = IF self \in Prods THEN self ELSE NoCtx]
                  ELSE /\ TRUE
                       /\ UNCHANGED << irqOffT, taskOn >>
            /\ pc' = [pc EXCEPT ![self] = "c3"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                            pend, inIrq, hook, active, freed, fr, ver, tg, 
                            tagE, infl, fcnt, rcnt, wins, passed, produced, 
                            credited, gone, viol, stack, xc, n, w, r, old, res, 
                            fl, we, st, fno, wfc, nr, fseen, b, coll, ci, wpos, 
                            staged, ok, valid, rbad, htag, k >>

c3(self) == /\ pc[self] = "c3"
            /\ IF FirstCheck /\ Fips /\ blocks # 0
                  THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                       /\ fseen' = fseen
                  ELSE /\ IF FirstCheck /\ Fips /\ PendReset
                             THEN /\ pc' = [pc EXCEPT ![self] = "c3p"]
                                  /\ fseen' = fseen
                             ELSE /\ fseen' = [fseen EXCEPT ![self] = fcnt]
                                  /\ pc' = [pc EXCEPT ![self] = "c4"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                            blocks, pend, inIrq, irqOffT, taskOn, hook, active, 
                            freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                            passed, produced, credited, gone, viol, stack, xc, 
                            n, w, r, old, res, fl, we, st, fno, wfc, nr, g, b, 
                            coll, ci, wpos, staged, ok, valid, rbad, htag, k >>

c4(self) == /\ pc[self] = "c4"
            /\ IF SumAvail(Cpus) < Blocks * Need
                  THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "cb"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                            blocks, pend, inIrq, irqOffT, taskOn, hook, active, 
                            freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                            passed, produced, credited, gone, viol, stack, xc, 
                            n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                            fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                            htag, k >>

cb(self) == /\ pc[self] = "cb"
            /\ IF b[self] < Blocks
                  THEN /\ pc' = [pc EXCEPT ![self] = "cl0"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "cf0"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                            blocks, pend, inIrq, irqOffT, taskOn, hook, active, 
                            freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                            passed, produced, credited, gone, viol, stack, xc, 
                            n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                            fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                            htag, k >>

cl0(self) == /\ pc[self] = "cl0"
             /\ lock = NoCtx /\ Run(self)
                /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self})
             /\ lock' = self
             /\ IF ~IsIrq(self)
                   THEN /\ IF IrqSave
                              THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = TRUE]
                              ELSE /\ TRUE
                                   /\ UNCHANGED irqOffT
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "cl1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, fr, ver, tg, 
                             tagE, infl, fcnt, rcnt, wins, passed, produced, 
                             credited, gone, viol, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

cl1(self) == /\ pc[self] = "cl1"
             /\ Run(self)
             /\ rpPendGen' = gen
             /\ lock' = NoCtx
             /\ IF ~IsIrq(self)
                   THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = self \in Prods /\ SchedIrqOff]
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = IF self \in Prods THEN self ELSE NoCtx]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "cl2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, mtx, blocks, pend, 
                             inIrq, hook, active, freed, fr, ver, tg, tagE, 
                             infl, fcnt, rcnt, wins, passed, produced, 
                             credited, gone, viol, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

cl2(self) == /\ pc[self] = "cl2"
             /\ IF ci[self] <= NC /\ coll[self] < Need
                   THEN /\ wpos' = [wpos EXCEPT ![self] = wp[ci[self]]]
                        /\ pc' = [pc EXCEPT ![self] = "cl3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cl4"]
                        /\ wpos' = wpos
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, fseen, b, coll, ci, staged, ok, 
                             valid, rbad, htag, k >>

cl3(self) == /\ pc[self] = "cl3"
             /\ LET rpos == rp[ci[self]] IN
                  LET u == Min(Need - coll[self], Min(Dist(wpos[self], rpos), N)) IN
                    /\ IF u > 0
                          THEN /\ staged' = [staged EXCEPT ![self] =       staged[self] \cup
                                                                     {<<ci[self], (rpos + j) % N, ver[ci[self]][(rpos + j) % N]>> :
                                                                      j \in 0..u-1}]
                               /\ rpPend' = [rpPend EXCEPT ![ci[self]] = (rpos + u) % N]
                               /\ mask' = (mask \cup {ci[self]})
                               /\ coll' = [coll EXCEPT ![self] = coll[self] + u]
                          ELSE /\ TRUE
                               /\ UNCHANGED << rpPend, mask, coll, staged >>
                    /\ ci' = [ci EXCEPT ![self] = ci[self] + 1]
             /\ pc' = [pc EXCEPT ![self] = "cl2"]
             /\ UNCHANGED << wp, rp, gen, rpPendGen, lock, mtx, blocks, pend, 
                             inIrq, irqOffT, taskOn, hook, active, freed, fr, 
                             ver, tg, tagE, infl, fcnt, rcnt, wins, passed, 
                             produced, credited, gone, viol, stack, xc, n, w, 
                             r, old, res, fl, we, st, fno, wfc, nr, g, fseen, 
                             b, wpos, ok, valid, rbad, htag, k >>

cl4(self) == /\ pc[self] = "cl4"
             /\ IF coll[self] < Need
                   THEN /\ mask' = {}
                        /\ pc' = [pc EXCEPT ![self] = "c9"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hs1"]
                        /\ mask' = mask
             /\ UNCHANGED << wp, rp, rpPend, gen, rpPendGen, lock, mtx, blocks, 
                             pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                             fr, ver, tg, tagE, infl, fcnt, rcnt, wins, passed, 
                             produced, credited, gone, viol, stack, xc, n, w, 
                             r, old, res, fl, we, st, fno, wfc, nr, g, fseen, 
                             b, coll, ci, wpos, staged, ok, valid, rbad, htag, 
                             k >>

hs1(self) == /\ pc[self] = "hs1"
             /\ \/ /\ ok' = [ok EXCEPT ![self] = TRUE]
                   /\ rbad' = [rbad EXCEPT ![self] = rbad[self] \cup Bad(staged[self])]
                   /\ htag' = [htag EXCEPT ![self] = htag[self] \cup Tags(staged[self])]
                \/ /\ SeedFail
                   /\ ok' = [ok EXCEPT ![self] = FALSE]
                   /\ UNCHANGED <<rbad, htag>>
             /\ pc' = [pc EXCEPT ![self] = "rl0"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, fseen, b, coll, ci, wpos, staged, 
                             valid, k >>

rl0(self) == /\ pc[self] = "rl0"
             /\ lock = NoCtx /\ Run(self)
                /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self})
             /\ lock' = self
             /\ IF ~IsIrq(self)
                   THEN /\ IF IrqSave
                              THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = TRUE]
                              ELSE /\ TRUE
                                   /\ UNCHANGED irqOffT
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "rl1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, fr, ver, tg, 
                             tagE, infl, fcnt, rcnt, wins, passed, produced, 
                             credited, gone, viol, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

rl1(self) == /\ pc[self] = "rl1"
             /\ Run(self)
             /\ valid' = [valid EXCEPT ![self] = gen = rpPendGen]
             /\ IF gen = rpPendGen
                   THEN /\ gone' = gone + Cardinality(staged[self])
                        /\ fr' = [c \in Cpus |->
                                  [i \in Slot |->
                                   fr[c][i]
                                   /\ ~(c \in mask
                                        /\ Dist(i, rp[c]) < Dist(rpPend[c], rp[c]))]]
                        /\ rp' = [c \in Cpus |-> IF c \in mask THEN rpPend[c] ELSE rp[c]]
                   ELSE /\ TRUE
                        /\ UNCHANGED << rp, fr, gone >>
             /\ lock' = NoCtx
             /\ IF ~IsIrq(self)
                   THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = self \in Prods /\ SchedIrqOff]
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = IF self \in Prods THEN self ELSE NoCtx]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "rl2"]
             /\ UNCHANGED << wp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, ver, tg, tagE, 
                             infl, fcnt, rcnt, wins, passed, produced, 
                             credited, viol, stack, xc, n, w, r, old, res, fl, 
                             we, st, fno, wfc, nr, g, fseen, b, coll, ci, wpos, 
                             staged, ok, rbad, htag, k >>

rl2(self) == /\ pc[self] = "rl2"
             /\ mask' = {}
             /\ IF ~(valid[self] /\ ok[self])
                   THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                        /\ UNCHANGED << b, coll, ci, staged, ok, valid >>
                   ELSE /\ b' = [b EXCEPT ![self] = b[self] + 1]
                        /\ coll' = [coll EXCEPT ![self] = 0]
                        /\ ci' = [ci EXCEPT ![self] = 1]
                        /\ staged' = [staged EXCEPT ![self] = {}]
                        /\ valid' = [valid EXCEPT ![self] = FALSE]
                        /\ ok' = [ok EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "cb"]
             /\ UNCHANGED << wp, rp, rpPend, gen, rpPendGen, lock, mtx, blocks, 
                             pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                             fr, ver, tg, tagE, infl, fcnt, rcnt, wins, passed, 
                             produced, credited, gone, viol, stack, xc, n, w, 
                             r, old, res, fl, we, st, fno, wfc, nr, g, fseen, 
                             wpos, rbad, htag, k >>

cf0(self) == /\ pc[self] = "cf0"
             /\ IF FinalCheck /\ Fips /\ blocks # 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                        /\ fseen' = fseen
                   ELSE /\ IF FinalCheck /\ Fips /\ PendReset /\ FinalPend
                              THEN /\ fseen' = [fseen EXCEPT ![self] = fcnt]
                                   /\ pc' = [pc EXCEPT ![self] = "cfp"]
                              ELSE /\ IF FinalCheck
                                         THEN /\ fseen' = [fseen EXCEPT ![self] = fcnt]
                                         ELSE /\ TRUE
                                              /\ fseen' = fseen
                                   /\ pc' = [pc EXCEPT ![self] = "cf1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

cf1(self) == /\ pc[self] = "cf1"
             /\ lock = NoCtx /\ Run(self)
                /\ (IsIrq(self) \/ taskOn[CpuOf(self)] \in {NoCtx, self})
             /\ lock' = self
             /\ IF ~IsIrq(self)
                   THEN /\ IF IrqSave
                              THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = TRUE]
                              ELSE /\ TRUE
                                   /\ UNCHANGED irqOffT
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = self]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "cf2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, fr, ver, tg, 
                             tagE, infl, fcnt, rcnt, wins, passed, produced, 
                             credited, gone, viol, stack, xc, n, w, r, old, 
                             res, fl, we, st, fno, wfc, nr, g, fseen, b, coll, 
                             ci, wpos, staged, ok, valid, rbad, htag, k >>

cf2(self) == /\ pc[self] = "cf2"
             /\ Run(self)
             /\ IF gen = g[self]
                   THEN /\ viol' = (viol \cup rbad[self] \cup Old(htag[self], fseen[self], rcnt))
                        /\ credited' = credited + Blocks * Need
                   ELSE /\ TRUE
                        /\ UNCHANGED << credited, viol >>
             /\ lock' = NoCtx
             /\ IF ~IsIrq(self)
                   THEN /\ irqOffT' = [irqOffT EXCEPT ![CpuOf(self)] = self \in Prods /\ SchedIrqOff]
                        /\ taskOn' = [taskOn EXCEPT ![CpuOf(self)] = IF self \in Prods THEN self ELSE NoCtx]
                   ELSE /\ TRUE
                        /\ UNCHANGED << irqOffT, taskOn >>
             /\ pc' = [pc EXCEPT ![self] = "c9"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, mtx, blocks, 
                             pend, inIrq, hook, active, freed, fr, ver, tg, 
                             tagE, infl, fcnt, rcnt, wins, passed, produced, 
                             gone, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, fseen, b, coll, ci, wpos, staged, 
                             ok, valid, rbad, htag, k >>

c9(self) == /\ pc[self] = "c9"
            /\ mtx' = NoCtx
            /\ b' = [b EXCEPT ![self] = 0]
            /\ coll' = [coll EXCEPT ![self] = 0]
            /\ ci' = [ci EXCEPT ![self] = 1]
            /\ wpos' = [wpos EXCEPT ![self] = 0]
            /\ staged' = [staged EXCEPT ![self] = {}]
            /\ ok' = [ok EXCEPT ![self] = FALSE]
            /\ valid' = [valid EXCEPT ![self] = FALSE]
            /\ rbad' = [rbad EXCEPT ![self] = {}]
            /\ htag' = [htag EXCEPT ![self] = {}]
            /\ g' = [g EXCEPT ![self] = 0]
            /\ fseen' = [fseen EXCEPT ![self] = 0]
            /\ pc' = [pc EXCEPT ![self] = "c0"]
            /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, blocks, 
                            pend, inIrq, irqOffT, taskOn, hook, active, freed, 
                            fr, ver, tg, tagE, infl, fcnt, rcnt, wins, passed, 
                            produced, credited, gone, viol, stack, xc, n, w, r, 
                            old, res, fl, we, st, fno, wfc, nr, k >>

c3p(self) == /\ pc[self] = "c3p"
             /\ IF pend # 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                        /\ fseen' = fseen
                   ELSE /\ fseen' = [fseen EXCEPT ![self] = fcnt]
                        /\ pc' = [pc EXCEPT ![self] = "c4"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, b, coll, ci, wpos, staged, ok, 
                             valid, rbad, htag, k >>

cfp(self) == /\ pc[self] = "cfp"
             /\ IF pend # 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "c9"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cf1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, fseen, b, coll, ci, wpos, staged, 
                             ok, valid, rbad, htag, k >>

cs(self) == c0(self) \/ c1(self) \/ c2(self) \/ c3(self) \/ c4(self)
               \/ cb(self) \/ cl0(self) \/ cl1(self) \/ cl2(self)
               \/ cl3(self) \/ cl4(self) \/ hs1(self) \/ rl0(self)
               \/ rl1(self) \/ rl2(self) \/ cf0(self) \/ cf1(self)
               \/ cf2(self) \/ c9(self) \/ c3p(self) \/ cfp(self)

nf0(self) == /\ pc[self] = "nf0"
             /\ IF k[self] < MaxResets
                   THEN /\ k' = [k EXCEPT ![self] = k[self] + 1]
                        /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ringReset",
                                                                    pc        |->  "nf0",
                                                                    xc        |->  xc[self] ] >>
                                                                \o stack[self]]
                           /\ xc' = [xc EXCEPT ![self] = "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, xc, k >>
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, n, w, r, old, res, fl, we, st, fno, wfc, nr, 
                             g, fseen, b, coll, ci, wpos, staged, ok, valid, 
                             rbad, htag >>

nt(self) == nf0(self)

ex0(self) == /\ pc[self] = "ex0"
             /\ \A q \in ConsProcs : pc[q] = "Done"
             /\ hook' = FALSE
             /\ pc' = [pc EXCEPT ![self] = "ex1"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, active, 
                             freed, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             passed, produced, credited, gone, viol, stack, xc, 
                             n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                             fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                             htag, k >>

ex1(self) == /\ pc[self] = "ex1"
             /\ IF RcuSync
                   THEN /\ \A q \in Prods : ~active[q]
                   ELSE /\ TRUE
             /\ pc' = [pc EXCEPT ![self] = "ex2"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, freed, fr, ver, tg, tagE, infl, fcnt, 
                             rcnt, wins, passed, produced, credited, gone, 
                             viol, stack, xc, n, w, r, old, res, fl, we, st, 
                             fno, wfc, nr, g, fseen, b, coll, ci, wpos, staged, 
                             ok, valid, rbad, htag, k >>

ex2(self) == /\ pc[self] = "ex2"
             /\ freed' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << wp, rp, rpPend, mask, gen, rpPendGen, lock, mtx, 
                             blocks, pend, inIrq, irqOffT, taskOn, hook, 
                             active, fr, ver, tg, tagE, infl, fcnt, rcnt, wins, 
                             passed, produced, credited, gone, viol, stack, xc, 
                             n, w, r, old, res, fl, we, st, fno, wfc, nr, g, 
                             fseen, b, coll, ci, wpos, staged, ok, valid, rbad, 
                             htag, k >>

ex(self) == ex0(self) \/ ex1(self) \/ ex2(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in ProcSet: ringReset(self))
           \/ (\E self \in Prods: p(self))
           \/ (\E self \in ConsProcs: cs(self))
           \/ (\E self \in NotifProcs: nt(self))
           \/ (\E self \in ExitProcs: ex(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Prods : WF_vars(p(self)) /\ WF_vars(ringReset(self))
        /\ \A self \in ConsProcs : WF_vars(cs(self))
        /\ \A self \in NotifProcs : WF_vars(nt(self)) /\ WF_vars(ringReset(self))
        /\ \A self \in ExitProcs : WF_vars(ex(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ wp \in [Cpus -> Slot]
    /\ rp \in [Cpus -> Slot]
    /\ blocks \in 0..SB+1
    /\ pend \in 0..Cardinality(Prods)
    /\ passed \in BOOLEAN
    /\ gone \in Nat
    /\ lock \in Prods \cup ConsProcs \cup {Notif, Exit, NoCtx}
    /\ produced <= Cardinality(Prods) * MaxEv

\* A producer never writes a slot that holds an event not consumed.
NoOverrun == "Overrun" \notin viol

\* Every credited block hashed events that were never handed out or
\* discarded before: no double credit when readers, producers and resets
\* race.
NoStaleCredit == "Stale" \notin viol

\* No slot of a credited block was overwritten between its collection and
\* the hash.
HashIntact == "Overwritten" \notin viol

\* The entropy credited never exceeds the events stored by the producers,
\* each one passed by the health tests.
CreditBound == credited <= produced

\* No credited event was sampled before a reset that completed before the
\* request compared the generation at its end - before the request or
\* during it -, but for one stored concurrently with a reset.
NoPreResetCredit == "PreReset" \notin viol
NoPreResetCreditStrict == "PreResetSurv" \notin viol

\* No credited event was sampled before a health test failure that came
\* before the request's last check of the startup test, but for one stored
\* concurrently with a reset.
NoPreFailureCredit == "PreFail" \notin viol
NoPreFailureCreditStrict == "PreFailSurv" \notin viol

\* No credited event was sampled within the APT window of a failure, which
\* the window's completion discards, but for one stored concurrently with a
\* reset.
NoWindowCredit == "Window" \notin viol
NoWindowCreditStrict == "WindowSurv" \notin viol

\* esdm_es_ring_reset(): what survives a reset is the event each producer
\* stores concurrently with it, at most one per producer context of a CPU.
SurvivorBound ==
    \A c \in Cpus :
        Cardinality({i \in Slot : InRing(c, i) /\ fr[c][i]
                                   /\ tg[c][i].rc < rcnt})
            <= Cardinality({q \in Prods : CpuOf(q) = c})

\* No interrupt spins on the ring lock held by a task context of its own
\* CPU, which cannot run before the interrupt returns.
NoSelfDeadlock ==
    ~\E q \in IrqCpus :
        /\ pc[q] = "rr1"
        /\ lock \notin {NoCtx, q}
        /\ ~IsIrq(lock)
        /\ CpuOf(lock) = q

\* No producer writes the ring arrays after module exit freed them.
NoUseAfterFree == "UseAfterFree" \notin viol

\* The rings lose no event and hand none out twice: every event stored is
\* in a ring until a block that hashed it is released, or a reset discards
\* it. The count of a release is what the block staged for the hash, not
\* what the read position moved by. By design, an event is not stored when
\* its ring is full, and the events of a released block are gone also when
\* the DRBG or the request fails after that.
NoEventLost == produced = SumAvail(Cpus) + gone

\* The events a ring holds, sampled before the given point and not stored
\* concurrently with a reset.
Held(Before(_)) ==
    {e \in Cpus \X Slot : /\ InRing(e[1], e[2]) /\ fr[e[1]][e[2]]
                          /\ ~tg[e[1]][e[2]].sv /\ Before(tg[e[1]][e[2]])}

\* The reset at the failure itself: once esdm_sp80090b_startup_restart()
\* of the first failure of a window did its reset, no ring holds an event
\* sampled before that failure, but for one stored concurrently with a
\* reset. Not stated for AtomicReset, where the producer does not learn
\* whether its failure was the first.
FailureDiscards ==
    \A q \in Prods :
        pc[q] \in {"hp1", "ht2"} /\ fl[q] /\ old[q] # SB + 1 /\ ~AtomicReset
            => LET Before(t) == t.fc < fno[q] IN Held(Before) = {}

\* The reset at the end of the window of a failure: once
\* esdm_sp80090b_startup() did it, no ring holds an event sampled within
\* that window, with the same exception.
WindowDiscards ==
    \A q \in Prods :
        pc[q] \in {"hp4", "ra1"} /\ we[q] /\ res[q] = SB /\ ~AtomicReset
            => LET Before(t) == t.win /\ t.fc <= wfc[q] IN Held(Before) = {}

\* Nothing is credited before the startup test passed for the first time.
StartupGate == credited > 0 => passed

\* The early return of esdm_sp80090b_startup(): while the startup test has
\* passed and no failure began, no change is in progress - the windows that
\* end at runtime fail no request.
NoIdleChange ==
    StartBlocks = 0 /\ fcnt = 0 /\ (\A q \in Prods : ~fl[q]) => pend = 0

-----------------------------------------------------------------------------
(* Liveness: Termination of the translation, every context finishes -  *)
(* no request, hook, notifier or module exit spins or waits forever. *)

-----------------------------------------------------------------------------
(* State constraints for three CPUs. TwoStalled is the scenario of two     *)
(* resets outstanding at once: only the first producer fails, and it ends  *)
(* no window; the others sample after that failure, which comes after the  *)
(* request began. FewSamples keeps the roles and leaves the order free:   *)
(* only the first producer fails, and it ends no window; the first and    *)
(* the second take one sample.                                            *)
TwoStalled ==
    /\ \A q \in Prods : fl[q] => q = 1
    /\ \A q \in Prods : we[q] => q # 1
    /\ \A q \in Prods \ {1} : n[q] > 0 => fcnt > 0
    /\ fcnt > 0 => \A q \in ConsProcs : nr[q] > 0

FewSamples ==
    /\ \A q \in Prods : fl[q] => q = 1
    /\ \A q \in Prods : we[q] => q # 1
    /\ n[1] <= 1
    /\ n[2] <= 1
=============================================================================
