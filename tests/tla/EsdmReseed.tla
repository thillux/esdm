----------------------------- MODULE EsdmReseed -----------------------------
(***************************************************************************)
(* Reseeding and output of the ESDM DRNG manager: esdm/esdm_drng_mgr.c and *)
(* the seeding state of esdm/esdm_es_mgr.c, at the granularity of their    *)
(* locks and atomics. One step is one atomic variable access or one        *)
(* critical section; the labels name the C functions they come from.      *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - Entropy is counted in units (128 bits, or 64 with SP800-90C           *)
(*   oversampling); a collection credits any amount from Yield up to what  *)
(*   it asks for, so that esdm_get_seed_buffers() skipping the sources is  *)
(*   the yield 0.                                                          *)
(* - Output is counted in units of 2^15 bits, the bit limits in the same.  *)
(* - The reseed interval and the request counter are one flag, due, which *)
(*   the environment raises at any time.                                   *)
(*   With PerRequest the interval is zero seconds, the mode in which every *)
(*   request reseeds its DRNG first; the mode is fixed per configuration.  *)
(* - The worker's waits and retry backoffs are left out: each reseed or    *)
(*   bring-up runs on a task thread, and a pass that would start none is   *)
(*   no step. Wakeups only shorten waits and are left out as well.         *)
(* - esdm_reset() is called after a VM generation change, by the thread    *)
(*   of esdm_es_events.c, followed by                                      *)
(*   esdm_force_fully_seeded_all_drbgs(); the admin process runs both at   *)
(*   any time. A reset voids the entropy collected before it: the ghosts   *)
(*   count a collection made before the entropy sources were reset as      *)
(*   nothing once the DRNG it is injected into was reset.                  *)
(* - The environment is bounded: every requester may stop after any of its *)
(*   calls, and time lets a reseed fall due MaxDue times or, with AnyDue,  *)
(*   any number of times until it stops. With all of it stopped the model  *)
(*   comes to rest in the state Quiet, where only the stutter step of the  *)
(*   environment is left; any other state without a step is a deadlock.    *)
(* - Not modelled: the request count limit, esdm_get_seed(), shutdown,     *)
(*   DRNG allocation, the node array lock and the self test gate.          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    NN,         \* DRNGs serving nodes; node 0 is the initial DRNG
    Req,        \* requester threads
    ReqKinds,   \* calls they make: "full", "fnb", "nb", "pr", "prnb"
    ReqSizes,   \* sizes of "full", "fnb" and "nb" requests, output units
    PRSizes,    \* request sizes of "pr" and "prnb", entropy units
    SS,         \* security strength, entropy units
    InitAdd,    \* initial seed oversampling, entropy units
    Osr,        \* entropy source oversampling, entropy units
    ES,         \* entropy sources credited with entropy
    Jent,       \* the Jitter RNG among them
    Yield,      \* entropy one source may credit per collection, has 0
    Ntg1,       \* ais2031_ntg1: two sources of NtgMin bits for a full seed
    JentNtg1,   \* es_jent_ntg1: the Jitter RNG alone is NTG.1
    NtgMin,     \* ESDM_AIS2031_NPTRNG_MIN_ENTROPY, entropy units
    Budgeted,   \* drng_max_reseed_bits configured (SP800-90C, DRG.4)
    MaxBits,    \* drng_max_reseed_bits, output units
    ThreshBits, \* drng_reseed_threshold_bits, output units
    Worker,     \* the asynchronous reseed worker is on duty
    Tasks,      \* its task threads, one per Jitter RNG collector
    Monitor,    \* the ES monitor triggers seedings
    MaxResets,  \* esdm_reset() calls, each followed by
                \* esdm_force_fully_seeded_all_drbgs()
    MaxForces,  \* esdm_drng_force_reseed() calls
    MaxDue,     \* times a reseed falls due by time
    AnyDue,     \* ... or any number of times, until time stops
    InjectFail, \* drng_seed() may fail
    CreditFailed, \* esdm_drng_seed_es() counts what a failed injection
                  \* collected, as the code did before its fix
    PRWaitInit,   \* the PR DRNG serves only once initially fully seeded
    FullRetry,    \* esdm_get_random_bytes_full() waits again when the ESDM
                  \* stopped since its wait
    PerRequest,   \* the reseed interval is zero seconds
    ResetEsFirst, \* esdm_reset() drops the entropy of the sources before it
                  \* resets the DRNGs, not after as before its fix
    ResetEpoch,   \* a collection begun before a reset of its DRNG is given
                  \* no credit, which it was before the fix
    PartialResets, \* a defect the code never had: every injection resets
                  \* the output count, not only one reaching the full seed
    Liveness    \* the environment eventually turns good

PR == NN
Nodes == 0..NN-1
Drngs == 0..NN
NoProc == "none"
NoTask == -1
Bringup == -2

WorkerProcs == IF Worker THEN {"worker"} ELSE {}
TaskProcs == IF Worker THEN Tasks ELSE {}
MonProcs == IF Monitor THEN {"monitor"} ELSE {}
AdminProcs == IF MaxResets + MaxForces > 0 THEN {"admin"} ELSE {}
AllProcs == Req \cup WorkerProcs \cup TaskProcs \cup MonProcs \cup AdminProcs
            \cup {"env"}

Min(a, b) == IF a < b THEN a ELSE b
SetMax(S) == CHOOSE x \in S : \A y \in S : y <= x
Big == 1000
\* A node DRNG starts a chunk below the maximum and completes it
UCap == MaxBits + SetMax(ReqSizes)
\* Ghost entropy counters saturate above every threshold they are held to
FCap == SS + InitAdd
\* Per source only NtgMin matters, and only with the NTG.1 strategy
ECap == IF Ntg1 THEN NtgMin ELSE 0

RECURSIVE SumSet(_, _)
SumSet(v, S) == IF S = {} THEN 0
                ELSE LET x == CHOOSE x \in S : TRUE IN v[x] + SumSet(v, S \ {x})
\* Entropy per source: the AIS 20/31 NTG.1 seeding rule of esdm_fully_seeded()
Ntg1Full(v) == \/ JentNtg1 /\ v[Jent] >= NtgMin
               \/ Cardinality({x \in ES : v[x] >= NtgMin}) >= 2
Delivered(v) == Cardinality({x \in ES : v[x] > 0})
AddV(a, b) == [x \in ES |-> IF a[x] + b[x] > ECap THEN ECap ELSE a[x] + b[x]]
ZeroV == [x \in ES |-> 0]

\* The worker looks at node 1 first and at node 0 last
PassOrder == [i \in 1..NN |-> i % NN]
RECURSIVE FirstK(_, _, _)
\* The first k nodes in PassOrder from position i on that are in S
FirstK(S, k, i) ==
    IF i > NN \/ k = 0 THEN <<>>
    ELSE IF PassOrder[i] \in S THEN <<PassOrder[i]>> \o FirstK(S, k - 1, i + 1)
    ELSE FirstK(S, k, i + 1)
TaskList == CHOOSE s \in [1..Cardinality(TaskProcs) -> TaskProcs] :
                \A i, j \in DOMAIN s : i # j => s[i] # s[j]
InSeq(s, S) == SelectSeq(s, LAMBDA x : x \in S)

(* --algorithm EsdmReseed {
variables
    fs = [d \in Drngs |-> FALSE],          \* fully_seeded
    force = [d \in Drngs |-> FALSE],       \* force_reseed
    initiated = [d \in Drngs |-> FALSE],
    used = [d \in Drngs |-> 0],            \* request_bits_since_fully_seeded
    due = [d \in Drngs |-> FALSE],         \* reseed interval or count
    lock = [d \in Drngs |-> NoProc],       \* drng->lock
    seedLock = [d \in Drngs |-> NoProc],   \* drng->seed_lock
    operational = FALSE,                   \* esdm_state.esdm_operational
    allSeeded = FALSE,                     \* all_online_nodes_seeded
    reseedRunning = [d \in Drngs |-> FALSE],
    running = 0,                           \* esdm_drng_reseed_running
    bringups = 0,                          \* esdm_drng_reseed_bringups
    task = [t \in TaskProcs |-> NoTask],
    prLock = NoProc,                       \* esdm_pr_lock
    resets = 0,                            \* calls of esdm_reset() made
    forces = 0,                            \* ... of esdm_drng_force_reseed()
    dues = 0,                              \* reseeds fallen due by time
    resetGen = [d \in Drngs |-> 0],        \* reset_generation
    esGen = 0,          \* resets of the entropy sources, a ghost
    swRet = [p \in AdminProcs |-> FALSE],  \* result of seedWork
    good = FALSE,       \* sources deliver, collectors free, no failures
    \* return values of the procedures
    rv = [p \in AllProcs |-> 0],
    injRet = [p \in AllProcs |-> 0],
    \* ghosts: entropy injected since the last output or reset, in all and
    \* per source; whether the seed a DRNG serves from met the seeding rule;
    \* the output since the last seed that met it; whether a requester
    \* seeded for its next chunk; properties violated
    freshOut = [d \in Drngs |-> 0],
    freshES = [d \in Drngs |-> ZeroV],
    goodSeed = [d \in Drngs |-> FALSE],
    outSince = [d \in Drngs |-> 0],
    tried = [p \in Req |-> FALSE],
    viol = {};

define {
    \* esdm_drng_budget()
    Budget(d, u) ==
        IF ~Budgeted THEN Big
        ELSE LET m == IF d = 0 THEN Min(MaxBits, ThreshBits) ELSE MaxBits
             IN IF u < m THEN m - u ELSE 0
    UsedAfter(u, t) == IF Budgeted THEN Min(u + t, UCap) ELSE 0
    \* esdm_drng_must_reseed()
    MustReseed(d) == \/ PerRequest \/ due[d] \/ force[d]
                     \/ (Budgeted /\ used[d] >= ThreshBits)
    \* esdm_drng_check_disable_threshold() without the request count limit
    Disable(d) == Budgeted /\ used[d] >= MaxBits
    \* esdm_drng_reseed_due()
    ReseedDue(d) == fs[d] /\ (\/ Budget(d, used[d]) = 0
                              \/ ~PerRequest /\ MustReseed(d))
    \* esdm_get_seed_entropy_osr()
    SeedReq(dfi, fe) ==
        SS + (IF dfi THEN InitAdd ELSE 0) + (IF fe THEN Osr ELSE 0)
    \* do_full_init of esdm_drng_seed_es()
    Dfi(d) == IF d = PR THEN ~initiated[PR] ELSE ~fs[d]
    \* es_delivered_threshold of esdm_drng_seed_es()
    Thr(d) == IF Ntg1 /\ Dfi(d) /\ ~JentNtg1 THEN 2 ELSE 1
    \* Entropy needed to be declared fully seeded: an unseeded DRNG and the
    \* first seed of the PR DRNG need the initial seed size.
    Need(d) == SS + (IF Dfi(d) THEN InitAdd ELSE 0)
    \* esdm_fully_seeded(): cv per source, ct in all
    FullTest(dfi, ct, cv) ==
        IF Ntg1 /\ dfi THEN Ntg1Full(cv) ELSE ct >= SeedReq(dfi, FALSE)
    \* what one collection credits, per source
    Collect(req) == IF good THEN {[x \in ES |-> req]}
                    ELSE [ES -> {y \in Yield : y <= req}]
    InjOK == IF InjectFail /\ ~good THEN BOOLEAN ELSE {TRUE}
    \* The seeding rule met by the entropy injected since the last output,
    \* counting this injection of yv
    Legit(d, yv) ==
        IF Ntg1 /\ Dfi(d) THEN Ntg1Full(AddV(freshES[d], yv))
        ELSE Min(freshOut[d] + SumSet(yv, ES), FCap) >= Need(d)
    \* Entropy only: the seed material is longer, every source fills its
    \* slot with the data of what is asked for. NTG.1 judges the seed of a
    \* DRNG not fully seeded by its own rule, 240 bits of entropy from two
    \* sources or an NTG.1 Jitter RNG, in at least 256 bits of material.
    CreditViol(d, full, yv) ==
        IF ~full THEN {}
        ELSE IF Ntg1 /\ Dfi(d)
        THEN IF Ntg1Full(AddV(freshES[d], yv)) THEN {} ELSE {"Ntg1Seed"}
        ELSE IF Min(freshOut[d] + SumSet(yv, ES), FCap) < Need(d)
        THEN {"CreditSinceOutput"} ELSE {}
    \* What the reseed worker starts in a pass: the reseeds due, node 0 (the
    \* initial DRNG) last, then one bring-up per unseeded DRNG, counting
    \* those under way, while task threads are free
    FreeTasks == InSeq(TaskList, {x \in TaskProcs : task[x] = NoTask})
    Starts == FirstK({d \in Nodes : ~reseedRunning[d] /\ ReseedDue(d)},
                     Len(FreeTasks), 1)
    Unseeded == Cardinality({d \in Nodes : ~fs[d]})
    NewBringups == Min(IF Unseeded > bringups THEN Unseeded - bringups ELSE 0,
                       Len(FreeTasks) - Len(Starts))
    \* The final state: the requesters and the administrator are done, the
    \* worker, its tasks and the ES monitor wait for work.
    Quiet ==
        /\ \A p \in Req \cup AdminProcs : pc[p] = "Done"
        /\ \A p \in TaskProcs : pc[p] = "tk0" /\ task[p] = NoTask
        /\ \A p \in WorkerProcs : pc[p] = "wk"
        /\ \A p \in MonProcs : pc[p] = "mo0"
}

\* esdm_unset_fully_seeded(), the caller holds lock[ud]
procedure unset(ud)
{
us1: fs[ud] := FALSE;
     goodSeed[ud] := FALSE;
us2: allSeeded := FALSE;
     if (ud = 0) operational := FALSE;
     return;
}

\* esdm_drngs_note_all_seeded()
procedure noteAll()
{
na1: allSeeded := TRUE;
na2: if (\E d \in Nodes : ~fs[d]) allSeeded := FALSE;
     return;
}

\* esdm_drng_seed_es(): the caller holds lock[sd], or with lockMode it is
\* taken for each injection, and passes do_full_init and forced as it finds
\* them, and the number of sources that keep the emergency reseeding going.
\* Each pass of se1 is one collection and one esdm_drng_inject(). Returns
\* the entropy injected in injRet. With lockMode the collections are made
\* without the lock: ep is the reset generation of the DRNG and eg the one of
\* the entropy sources when a collection begins, here with the call and with
\* the step of the injection before.
procedure seedEs(sd, lockMode, dfi, forced, thr, ep, eg)
    variables coll = 0, collV = ZeroV, injd = 0, seeded = FALSE;
{
se1: if (lockMode) await lock[sd] = NoProc;
     with (req = SeedReq(dfi, ~dfi /\ sd = PR),
           \* one taken out of the fully seeded state needs more
           dfi2 = dfi \/ (lockMode /\ ~fs[sd]),
           yv \in Collect(req),
           ok \in InjOK,
           \* esdm_reset() since the collection began: no credit for it
           \* nor for the ones before
           stale = ResetEpoch /\ lockMode /\ ep # resetGen[sd],
           y = IF stale THEN 0 ELSE SumSet(yv, ES),
           c = IF stale THEN 0 ELSE Min(coll + y, FCap + Osr),
           cv = IF stale THEN ZeroV ELSE AddV(collV, yv),
           full = FullTest(dfi2, c, cv) /\ (sd # PR \/ dfi2 \/ c >= req),
           \* the emergency reseeding loop goes on
           again = forced /\ ~(ok /\ full) /\ Delivered(yv) >= thr,
           seeded2 = seeded \/ ok,
           injd2 = IF ok THEN Min(injd + y, FCap + Osr) ELSE injd,
           \* ghost: what the collection is worth, nothing if it was made
           \* before the sources were reset and the DRNG has been reset
           gv = IF (IF lockMode THEN eg ELSE esGen) < resetGen[sd]
                THEN ZeroV ELSE yv,
           g = SumSet(gv, ES)) {
         if (ok) {
             viol := viol \cup CreditViol(sd, full, gv);
             goodSeed[sd] := IF full THEN Legit(sd, gv)
                             ELSE fs[sd] /\ goodSeed[sd];
             freshOut[sd] := Min(freshOut[sd] + g, FCap);
             freshES[sd] := AddV(freshES[sd], gv);
             if (full \/ PartialResets) used[sd] := 0;
             if (full /\ Legit(sd, gv)) outSince[sd] := 0;
             due[sd] := FALSE;
             force[sd] := FALSE;
             if (~fs[sd] /\ full) {
                 fs[sd] := TRUE;
                 initiated[sd] := TRUE;
             };
         } else {
             force[sd] := TRUE;
         };
         if (again) {
             dfi := dfi2;
             coll := IF ok \/ CreditFailed \/ stale THEN c ELSE coll;
             collV := IF ok \/ CreditFailed \/ stale THEN cv ELSE collV;
             seeded := seeded2;
             injd := injd2;
             ep := resetGen[sd];
             eg := esGen;
             goto se1;
         } else if (lockMode /\ seeded2 /\ sd = 0) {
             goto se2;
         } else {
             \* esdm_init_ops(), under the lock the caller holds
             if (seeded2 /\ sd = 0 /\ (fs[0] \/ (ok /\ full)))
                 operational := TRUE;
             if (sd = PR) injRet[self] := injd2;
             return;
         };
     };
     \* esdm_init_ops(), the lock taken again
se2: await lock[0] = NoProc;
     if (fs[0]) operational := TRUE;
     return;
}

\* esdm_drng_seed()
procedure seed(sdd)
{
sdA: await lock[sdd] = NoProc;
     lock[sdd] := self;
     call seedEs(sdd, FALSE, Dfi(sdd), force[sdd] \/ Dfi(sdd), Thr(sdd),
                 0, 0);
sdB: lock[sdd] := NoProc;
     return;
}

\* esdm_drng_reseed_seed_locked(), the caller holds seedLock[rsd]
procedure reseedLocked(rsd)
    variables rep = 0, reg = 0;
{
rs0: if (PerRequest /\ self \in Req) tried[self] := TRUE;
     if (rsd = PR \/ ~fs[rsd]) {
         call seed(rsd);
         return;
     } else if (Budget(rsd, used[rsd]) = 0) {
         \* spent: forced, adding up collections, locked per injection
         force[rsd] := TRUE;
         call seedEs(rsd, TRUE, Dfi(rsd), TRUE, Thr(rsd), resetGen[rsd],
                     esGen);
         return;
     } else {
         \* the collection begins, without the lock
         rep := resetGen[rsd];
         reg := esGen;
     };
     \* the injection under the lock
rs1: await lock[rsd] = NoProc;
     with (yv \in Collect(SS), ok \in InjOK,
           y = SumSet(yv, ES),
           \* esdm_reset() since the collection began: no credit
           stale = ResetEpoch /\ rep # resetGen[rsd],
           full = ~stale /\ FullTest(~fs[rsd], y, yv),
           gv = IF reg < resetGen[rsd] THEN ZeroV ELSE yv,
           g = SumSet(gv, ES)) {
         if (ok) {
             viol := viol \cup CreditViol(rsd, full, gv);
             goodSeed[rsd] := IF full THEN Legit(rsd, gv)
                              ELSE fs[rsd] /\ goodSeed[rsd];
             freshOut[rsd] := Min(freshOut[rsd] + g, FCap);
             freshES[rsd] := AddV(freshES[rsd], gv);
             if (full \/ PartialResets) used[rsd] := 0;
             if (full /\ Legit(rsd, gv)) outSince[rsd] := 0;
             due[rsd] := FALSE;
             force[rsd] := FALSE;
             if (~fs[rsd] /\ full) {
                 fs[rsd] := TRUE;
                 initiated[rsd] := TRUE;
             };
             if (rsd = 0 /\ (fs[rsd] \/ full)) operational := TRUE;
         } else {
             force[rsd] := TRUE;
         };
     };
     return;
}

\* __esdm_drng_seed_work(); its result, whether the DRNG is fully seeded now
\* or all are, is kept for esdm_force_fully_seeded_all_drbgs() only: for the
\* worker it sets the retry backoff, which is left out
procedure seedWork(swForce, swWait)
    variables i = 0, sel = NoTask, busy = NoTask;
{
sw1: while (i < NN) {
         if (fs[i]) {
             i := i + 1;
         } else if (seedLock[i] # NoProc) {
             if (busy = NoTask) busy := i;
             i := i + 1;
         } else {
             \* trylock and the look again: only a holder of seedLock[i]
             \* makes it fully seeded
             seedLock[i] := self;
             sel := i;
             i := NN;
         };
     };
sw2: if (sel # NoTask) {
         if (~fs[sel]) {
             if (swForce) force[sel] := TRUE;
             call seed(sel);
         };
sw3:     seedLock[sel] := NoProc;
         if (self \in AdminProcs) swRet[self] := fs[sel];
         return;
     } else if (busy # NoTask /\ swWait) {
         \* only a caller that may wait does, if no other is left
         await seedLock[busy] = NoProc;
         seedLock[busy] := self;
         sel := busy;
         goto sw2;
     } else if (busy # NoTask) {
         if (self \in AdminProcs) swRet[self] := FALSE;
         return;
     } else {
         if (self \in AdminProcs) swRet[self] := TRUE;
         call noteAll();
         return;
     };
}

\* esdm_drng_seed_work_try()
procedure seedWorkTry()
{
swt: either {
         call seedWork(FALSE, FALSE);
         return;
     } or {
         \* no Jitter RNG collector free
         await ~good;
         return;
     };
}

\* esdm_force_fully_seeded()
procedure forceFS()
{
ff: if (allSeeded) {
        return;
    } else {
        call seedWork(TRUE, TRUE);
        return;
    };
}

\* esdm_force_fully_seeded_all_drbgs(): one DRNG per pass, until a pass
\* does not fully seed its DRNG or esdm_es_reseed_wanted() finds all seeded
\* or too little entropy
procedure forceAll()
{
fa0: if (allSeeded) return;
fa1: call seedWork(TRUE, TRUE);
fa2: with (avail \in IF good THEN {TRUE} ELSE BOOLEAN) {
         if (swRet[self] /\ ~allSeeded /\ avail) {
             goto fa1;
         } else {
             return;
         };
     };
}

\* esdm_drng_get_reseed() of a node or the initial DRNG. The interval is
\* read twice, by esdm_drng_must_reseed() and
\* esdm_drng_reseed_async_capable(): one read here, the mode is fixed.
procedure getReseed(rd, rnb)
{
gr0: if (~MustReseed(rd)) {
         return;
     } else if (rd # 0 /\ Worker /\ ~PerRequest) {
         \* left to the worker, esdm_drng_reseed_kick()
         return;
     } else if (rnb) {
         either {
             await seedLock[rd] = NoProc;
             seedLock[rd] := self;
             if (MustReseed(rd)) call reseedLocked(rd);
         } or {
             \* being seeded, or no Jitter RNG collector free
             await seedLock[rd] # NoProc \/ ~good;
             force[rd] := TRUE;
             return;
         };
     } else {
         await seedLock[rd] = NoProc;
         seedLock[rd] := self;
         if (MustReseed(rd)) call reseedLocked(rd);
     };
gr1: seedLock[rd] := NoProc;
     return;
}

\* esdm_drng_get(); rv: units produced, -1 for -EOPNOTSUPP
procedure drngGet(gd, gnb, glen)
    variables processed = 0, exhausted = FALSE, stop = FALSE, uns = FALSE;
{
dg0: if (~operational) {
         rv[self] := -1;
         return;
     };
dg1: while (glen > 0) {
         if (gd = PR) {
             \* every chunk from a seed collected for it under the lock
             if (gnb /\ lock[PR] # NoProc) {
                 goto dg9;
             } else {
                 await lock[PR] = NoProc;
                 lock[PR] := self;
                 call seedEs(PR, FALSE, Dfi(PR), force[PR] \/ Dfi(PR), Thr(PR),
                             0, 0);
             };
dgP:         with (t = IF PRWaitInit /\ ~initiated[PR] THEN 0
                       ELSE Min(Min(glen, injRet[self] - Osr), SS)) {
                 if (t <= 0) {
                     stop := TRUE;
                 } else {
                     viol := viol
                         \cup (IF t > freshOut[PR] - Osr
                               THEN {"PROutput"} ELSE {})
                         \cup (IF ~initiated[PR] THEN {"PRInitiated"} ELSE {});
                     freshOut[PR] := 0;
                     freshES[PR] := ZeroV;
                     fs[PR] := FALSE;
                     goodSeed[PR] := FALSE;
                     processed := processed + t;
                     glen := glen - t;
                     stop := FALSE;
                 };
                 lock[PR] := NoProc;
                 injRet[self] := 0;
             };
             if (stop) goto dg9;
         } else {
             call getReseed(gd, gnb);
             \* lock, then the checks before every chunk and the chunk
dgN:         await lock[gd] = NoProc;
             with (f = fs[gd],
                   b = Budget(gd, used[gd]),
                   t = IF ~f THEN 0
                       ELSE IF gd = 0 THEN Min(glen, b)
                       ELSE IF b = 0 THEN 0 ELSE glen,
                   dis = Disable(gd),
                   gen = f /\ t > 0 /\ ~dis,
                   nu = IF gen THEN UsedAfter(used[gd], t) ELSE used[gd],
                   spent = gen /\ gd # 0 /\ Budget(gd, nu) = 0,
                   u = \/ f /\ ~gen /\ (IF gd = 0 THEN dis
                                        ELSE (b > 0 \/ ~Worker))
                       \/ spent /\ ~Worker) {
                 if (gen) {
                     viol := viol
                         \cup (IF Budgeted /\ gd # 0 /\ used[gd] >= MaxBits
                               THEN {"ChunkPastMax"} ELSE {})
                         \cup (IF Budgeted /\ gd = 0
                                  /\ nu > Min(MaxBits, ThreshBits)
                               THEN {"InitPastBudget"} ELSE {})
                         \cup (IF ~goodSeed[gd]
                               THEN {"OutputUnseeded"} ELSE {})
                         \cup (IF PerRequest /\ ~gnb /\ ~tried[self]
                               THEN {"NoReseed"} ELSE {});
                     used[gd] := nu;
                     outSince[gd] := IF Budgeted
                                     THEN Min(outSince[gd] + t, UCap) ELSE 0;
                     freshOut[gd] := 0;
                     freshES[gd] := ZeroV;
                     processed := processed + t;
                     glen := glen - t;
                 };
                 exhausted := exhausted \/ (f /\ ~gen) \/ spent;
                 stop := ~gen;
                 uns := u;
                 if (u) lock[gd] := self;
                 if (PerRequest) tried[self] := FALSE;
             };
             if (uns) {
                 call unset(gd);
             } else if (stop) {
                 goto dg9;
             } else {
                 goto dg1;
             };
dgU:         lock[gd] := NoProc;
             if (stop) goto dg9;
         };
     };
     \* the caller reseeds only without a worker on duty
dg9: if (exhausted /\ ~Worker) {
         if (gnb) call seedWorkTry() else call forceFS();
     } else {
         rv[self] := processed;
         return;
     };
dgR: rv[self] := processed;
     return;
}

\* esdm_drng_get_sleep()
procedure getSleep(spr, snb, slen)
    variables pick = 0;
{
gs0: if (spr) {
         pick := PR;
     } else {
         \* a node DRNG that is free, fully seeded and not spent, else
         \* the initial DRNG
         with (c = {j \in 1..NN-1 :
                    lock[j] = NoProc /\ fs[j] /\ Budget(j, used[j]) > 0},
               j \in IF c = {} THEN {0} ELSE c)
             pick := j;
     };
gs1: call drngGet(pick, snb, slen);
gs2: if (~spr /\ pick # 0 /\ rv[self] = 0) {
         call drngGet(0, snb, slen);
         return;
     } else {
         return;
     };
}

\* esdm_drng_sleep_while_nonoperational(); rv: 0, or -2 for -EAGAIN
procedure sleepNonop(snb2)
{
sn0: if (snb2) {
         if (~allSeeded) call seedWorkTry();
     } else {
         call forceFS();
     };
sn1: if (snb2) {
         rv[self] := IF operational THEN 0 ELSE -2;
         return;
     } else {
         await operational;
         rv[self] := 0;
         return;
     };
}

\* esdm_drng_reseed_one()
procedure reseedOne(od)
{
ro0: await seedLock[od] = NoProc;
     seedLock[od] := self;
     if (MustReseed(od)) call reseedLocked(od);
ro1: seedLock[od] := NoProc;
     return;
}

fair+ process (r \in Req)
    variables kind = "full", n = 0, done = 0;
{
rq0: while (TRUE) {
         with (k \in ReqKinds \cup {"stop"},
               s \in IF k = "stop" THEN {0}
                     ELSE IF k \in {"pr", "prnb"} THEN PRSizes ELSE ReqSizes) {
             kind := k;
             n := s;
         };
         if (kind = "stop") {
             \* the requester makes no further call
             goto Done;
         } else if (kind = "full") {
             \* esdm_get_random_bytes_full()
rqF:         while (done < n) {
                 call sleepNonop(FALSE);
rqF1:            call getSleep(FALSE, FALSE, n - done);
rqF2:            if (rv[self] < 0 /\ FullRetry) {
                     \* the ESDM stopped since the wait: wait again
                     goto rqF;
                 } else if (rv[self] < 0) {
                     \* a blocking request returns short or an error
                     viol := viol \cup {"FullShort"};
                     goto rqE;
                 } else {
                     done := done + rv[self];
                 };
             };
         } else if (kind = "fnb") {
             \* esdm_get_random_bytes_full_noblock()
             call sleepNonop(TRUE);
rqG1:        if (rv[self] < 0) {
                 goto rqE;
             } else {
                 call getSleep(FALSE, TRUE, n);
             };
         } else if (kind = "nb") {
             \* esdm_get_random_bytes()
             call getSleep(FALSE, TRUE, n);
         } else if (kind = "pr") {
             \* esdm_get_random_bytes_pr()
             call sleepNonop(FALSE);
rqP1:        if (prLock # NoProc) {
                 goto rqE;
             } else {
                 prLock := self;
                 call getSleep(TRUE, FALSE, n);
             };
rqP2:        prLock := NoProc;
         } else {
             \* esdm_get_random_bytes_pr_noblock()
             call sleepNonop(TRUE);
rqQ1:        if (rv[self] < 0 \/ prLock # NoProc) {
                 goto rqE;
             } else {
                 prLock := self;
                 call getSleep(TRUE, TRUE, n);
             };
rqQ2:        prLock := NoProc;
         };
rqE:     rv[self] := 0;
         kind := "full";
         n := 0;
         done := 0;
     };
}

\* esdm_drng_reseed_worker_run(): one esdm_drng_reseed_pass() per step
fair+ process (w \in WorkerProcs)
{
wk: while (TRUE) {
        \* a pass that starts nothing and has nothing to note is no step:
        \* the worker waits
        await \/ Len(Starts) + NewBringups > 0
              \/ (\A d \in Nodes : fs[d]) /\ ~allSeeded;
        with (free = FreeTasks, starts = Starts, nb = NewBringups) {
            task := [x \in TaskProcs |->
                     IF \E j \in 1..Len(starts) : free[j] = x
                     THEN starts[CHOOSE j \in 1..Len(starts) : free[j] = x]
                     ELSE IF \E j \in Len(starts)+1..Len(starts)+nb : free[j] = x
                     THEN Bringup ELSE task[x]];
            reseedRunning := [d \in Drngs |->
                              reseedRunning[d] \/ \E j \in 1..Len(starts) :
                                                    starts[j] = d];
            running := running + Len(starts) + nb;
            bringups := bringups + nb;
        };
        if ((\A d \in Nodes : fs[d]) /\ ~allSeeded) call noteAll();
    };
}

\* esdm_drng_reseed_task()
fair+ process (t \in TaskProcs)
{
tk0: while (TRUE) {
         await task[self] # NoTask;
         if (task[self] = Bringup) {
             call seedWork(TRUE, FALSE);
         } else {
             call reseedOne(task[self]);
         };
tk1:     if (task[self] = Bringup) {
             bringups := bringups - 1;
         } else {
             reseedRunning[task[self]] := FALSE;
         };
         running := running - 1;
         task[self] := NoTask;
     };
}

\* the ES monitor through esdm_es_add_entropy()
fair+ process (m \in MonProcs)
{
mo0: while (TRUE) {
         await ~allSeeded;
         call seedWorkTry();
     };
}

\* esdm_reset() and esdm_drng_force_reseed()
fair+ process (a \in AdminProcs)
    variables ai = 0;
{
ad0: while (resets < MaxResets \/ forces < MaxForces) {
         either {
             await resets < MaxResets;
             resets := resets + 1;
             \* esdm_es_reset(): the entropy of the sources is dropped
             if (ResetEsFirst) esGen := esGen + 1;
             \* esdm_drng_reset_locked() of every node DRNG
ad1:         while (ai < NN) {
                 await lock[ai] = NoProc;
                 used[ai] := 0;
                 fs[ai] := FALSE;
                 goodSeed[ai] := FALSE;
                 force[ai] := FALSE;
                 initiated[ai] := FALSE;
                 due[ai] := TRUE;
                 resetGen[ai] := resetGen[ai] + 1;
                 freshOut[ai] := 0;
                 freshES[ai] := ZeroV;
                 if (ai = 0) {
                     allSeeded := FALSE;
                     operational := FALSE;
                 };
                 ai := ai + 1;
             };
ad2:         await lock[PR] = NoProc;
             used[PR] := 0;
             fs[PR] := FALSE;
             goodSeed[PR] := FALSE;
             force[PR] := FALSE;
             initiated[PR] := FALSE;
             due[PR] := TRUE;
             resetGen[PR] := resetGen[PR] + 1;
             freshOut[PR] := 0;
             freshES[PR] := ZeroV;
             \* esdm_reset_state()
ad3:         allSeeded := FALSE;
             ai := 0;
             if (~ResetEsFirst) esGen := esGen + 1;
             \* esdm_es_events_handle() seeds all DRNGs anew
             call forceAll();
         } or {
             await forces < MaxForces;
             forces := forces + 1;
             if (Disable(0)) {
                 force[0] := fs[0];
             } else {
ad4:             while (ai < NN) {
                     force[ai] := fs[ai];
                     ai := ai + 1;
                 };
ad5:             ai := 0;
             };
         };
     };
}

\* time passes, a bounded number of times or until it stops; the entropy
\* sources may recover for good
process (e = "env")
{
en0: while (TRUE) {
         either {
             await AnyDue \/ dues < MaxDue;
             with (d \in Nodes) due[d] := TRUE;
             if (~AnyDue) dues := dues + 1;
         } or {
             await Liveness /\ ~good;
             good := TRUE;
         } or {
             await AnyDue;
             goto enQ;
         } or {
             \* the final state, once the others are at rest
             await ~AnyDue /\ Quiet;
         };
     };
     \* time has stopped: the final state, once the others are at rest
enQ: while (TRUE) {
         either {
             await Quiet;
         } or {
             await Liveness /\ ~good;
             good := TRUE;
         };
     };
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES fs, force, initiated, used, due, lock, seedLock, operational, 
          allSeeded, reseedRunning, running, bringups, task, prLock, resets, 
          forces, dues, resetGen, esGen, swRet, good, rv, injRet, freshOut, 
          freshES, goodSeed, outSince, tried, viol, pc, stack

(* define statement *)
Budget(d, u) ==
    IF ~Budgeted THEN Big
    ELSE LET m == IF d = 0 THEN Min(MaxBits, ThreshBits) ELSE MaxBits
         IN IF u < m THEN m - u ELSE 0
UsedAfter(u, t) == IF Budgeted THEN Min(u + t, UCap) ELSE 0

MustReseed(d) == \/ PerRequest \/ due[d] \/ force[d]
                 \/ (Budgeted /\ used[d] >= ThreshBits)

Disable(d) == Budgeted /\ used[d] >= MaxBits

ReseedDue(d) == fs[d] /\ (\/ Budget(d, used[d]) = 0
                          \/ ~PerRequest /\ MustReseed(d))

SeedReq(dfi, fe) ==
    SS + (IF dfi THEN InitAdd ELSE 0) + (IF fe THEN Osr ELSE 0)

Dfi(d) == IF d = PR THEN ~initiated[PR] ELSE ~fs[d]

Thr(d) == IF Ntg1 /\ Dfi(d) /\ ~JentNtg1 THEN 2 ELSE 1


Need(d) == SS + (IF Dfi(d) THEN InitAdd ELSE 0)

FullTest(dfi, ct, cv) ==
    IF Ntg1 /\ dfi THEN Ntg1Full(cv) ELSE ct >= SeedReq(dfi, FALSE)

Collect(req) == IF good THEN {[x \in ES |-> req]}
                ELSE [ES -> {y \in Yield : y <= req}]
InjOK == IF InjectFail /\ ~good THEN BOOLEAN ELSE {TRUE}


Legit(d, yv) ==
    IF Ntg1 /\ Dfi(d) THEN Ntg1Full(AddV(freshES[d], yv))
    ELSE Min(freshOut[d] + SumSet(yv, ES), FCap) >= Need(d)




CreditViol(d, full, yv) ==
    IF ~full THEN {}
    ELSE IF Ntg1 /\ Dfi(d)
    THEN IF Ntg1Full(AddV(freshES[d], yv)) THEN {} ELSE {"Ntg1Seed"}
    ELSE IF Min(freshOut[d] + SumSet(yv, ES), FCap) < Need(d)
    THEN {"CreditSinceOutput"} ELSE {}



FreeTasks == InSeq(TaskList, {x \in TaskProcs : task[x] = NoTask})
Starts == FirstK({d \in Nodes : ~reseedRunning[d] /\ ReseedDue(d)},
                 Len(FreeTasks), 1)
Unseeded == Cardinality({d \in Nodes : ~fs[d]})
NewBringups == Min(IF Unseeded > bringups THEN Unseeded - bringups ELSE 0,
                   Len(FreeTasks) - Len(Starts))


Quiet ==
    /\ \A p \in Req \cup AdminProcs : pc[p] = "Done"
    /\ \A p \in TaskProcs : pc[p] = "tk0" /\ task[p] = NoTask
    /\ \A p \in WorkerProcs : pc[p] = "wk"
    /\ \A p \in MonProcs : pc[p] = "mo0"

VARIABLES ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, collV, injd, 
          seeded, sdd, rsd, rep, reg, swForce, swWait, i, sel, busy, rd, rnb, 
          gd, gnb, glen, processed, exhausted, stop, uns, spr, snb, slen, 
          pick, snb2, od, kind, n, done, ai

vars == << fs, force, initiated, used, due, lock, seedLock, operational, 
           allSeeded, reseedRunning, running, bringups, task, prLock, resets, 
           forces, dues, resetGen, esGen, swRet, good, rv, injRet, freshOut, 
           freshES, goodSeed, outSince, tried, viol, pc, stack, ud, sd, 
           lockMode, dfi, forced, thr, ep, eg, coll, collV, injd, seeded, sdd, 
           rsd, rep, reg, swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
           glen, processed, exhausted, stop, uns, spr, snb, slen, pick, snb2, 
           od, kind, n, done, ai >>

ProcSet == (Req) \cup (WorkerProcs) \cup (TaskProcs) \cup (MonProcs) \cup (AdminProcs) \cup {"env"}

Init == (* Global variables *)
        /\ fs = [d \in Drngs |-> FALSE]
        /\ force = [d \in Drngs |-> FALSE]
        /\ initiated = [d \in Drngs |-> FALSE]
        /\ used = [d \in Drngs |-> 0]
        /\ due = [d \in Drngs |-> FALSE]
        /\ lock = [d \in Drngs |-> NoProc]
        /\ seedLock = [d \in Drngs |-> NoProc]
        /\ operational = FALSE
        /\ allSeeded = FALSE
        /\ reseedRunning = [d \in Drngs |-> FALSE]
        /\ running = 0
        /\ bringups = 0
        /\ task = [t \in TaskProcs |-> NoTask]
        /\ prLock = NoProc
        /\ resets = 0
        /\ forces = 0
        /\ dues = 0
        /\ resetGen = [d \in Drngs |-> 0]
        /\ esGen = 0
        /\ swRet = [p \in AdminProcs |-> FALSE]
        /\ good = FALSE
        /\ rv = [p \in AllProcs |-> 0]
        /\ injRet = [p \in AllProcs |-> 0]
        /\ freshOut = [d \in Drngs |-> 0]
        /\ freshES = [d \in Drngs |-> ZeroV]
        /\ goodSeed = [d \in Drngs |-> FALSE]
        /\ outSince = [d \in Drngs |-> 0]
        /\ tried = [p \in Req |-> FALSE]
        /\ viol = {}
        (* Procedure unset *)
        /\ ud = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure seedEs *)
        /\ sd = [ self \in ProcSet |-> defaultInitValue]
        /\ lockMode = [ self \in ProcSet |-> defaultInitValue]
        /\ dfi = [ self \in ProcSet |-> defaultInitValue]
        /\ forced = [ self \in ProcSet |-> defaultInitValue]
        /\ thr = [ self \in ProcSet |-> defaultInitValue]
        /\ ep = [ self \in ProcSet |-> defaultInitValue]
        /\ eg = [ self \in ProcSet |-> defaultInitValue]
        /\ coll = [ self \in ProcSet |-> 0]
        /\ collV = [ self \in ProcSet |-> ZeroV]
        /\ injd = [ self \in ProcSet |-> 0]
        /\ seeded = [ self \in ProcSet |-> FALSE]
        (* Procedure seed *)
        /\ sdd = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure reseedLocked *)
        /\ rsd = [ self \in ProcSet |-> defaultInitValue]
        /\ rep = [ self \in ProcSet |-> 0]
        /\ reg = [ self \in ProcSet |-> 0]
        (* Procedure seedWork *)
        /\ swForce = [ self \in ProcSet |-> defaultInitValue]
        /\ swWait = [ self \in ProcSet |-> defaultInitValue]
        /\ i = [ self \in ProcSet |-> 0]
        /\ sel = [ self \in ProcSet |-> NoTask]
        /\ busy = [ self \in ProcSet |-> NoTask]
        (* Procedure getReseed *)
        /\ rd = [ self \in ProcSet |-> defaultInitValue]
        /\ rnb = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure drngGet *)
        /\ gd = [ self \in ProcSet |-> defaultInitValue]
        /\ gnb = [ self \in ProcSet |-> defaultInitValue]
        /\ glen = [ self \in ProcSet |-> defaultInitValue]
        /\ processed = [ self \in ProcSet |-> 0]
        /\ exhausted = [ self \in ProcSet |-> FALSE]
        /\ stop = [ self \in ProcSet |-> FALSE]
        /\ uns = [ self \in ProcSet |-> FALSE]
        (* Procedure getSleep *)
        /\ spr = [ self \in ProcSet |-> defaultInitValue]
        /\ snb = [ self \in ProcSet |-> defaultInitValue]
        /\ slen = [ self \in ProcSet |-> defaultInitValue]
        /\ pick = [ self \in ProcSet |-> 0]
        (* Procedure sleepNonop *)
        /\ snb2 = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure reseedOne *)
        /\ od = [ self \in ProcSet |-> defaultInitValue]
        (* Process r *)
        /\ kind = [self \in Req |-> "full"]
        /\ n = [self \in Req |-> 0]
        /\ done = [self \in Req |-> 0]
        (* Process a *)
        /\ ai = [self \in AdminProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Req -> "rq0"
                                        [] self \in WorkerProcs -> "wk"
                                        [] self \in TaskProcs -> "tk0"
                                        [] self \in MonProcs -> "mo0"
                                        [] self \in AdminProcs -> "ad0"
                                        [] self = "env" -> "en0"]

us1(self) == /\ pc[self] = "us1"
             /\ fs' = [fs EXCEPT ![ud[self]] = FALSE]
             /\ goodSeed' = [goodSeed EXCEPT ![ud[self]] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "us2"]
             /\ UNCHANGED << force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, outSince, tried, viol, stack, 
                             ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                             collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                             swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, kind, n, done, ai >>

us2(self) == /\ pc[self] = "us2"
             /\ allSeeded' = FALSE
             /\ IF ud[self] = 0
                   THEN /\ operational' = FALSE
                   ELSE /\ TRUE
                        /\ UNCHANGED operational
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ud' = [ud EXCEPT ![self] = Head(stack[self]).ud]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             reseedRunning, running, bringups, task, prLock, 
                             resets, forces, dues, resetGen, esGen, swRet, 
                             good, rv, injRet, freshOut, freshES, goodSeed, 
                             outSince, tried, viol, sd, lockMode, dfi, forced, 
                             thr, ep, eg, coll, collV, injd, seeded, sdd, rsd, 
                             rep, reg, swForce, swWait, i, sel, busy, rd, rnb, 
                             gd, gnb, glen, processed, exhausted, stop, uns, 
                             spr, snb, slen, pick, snb2, od, kind, n, done, ai >>

unset(self) == us1(self) \/ us2(self)

na1(self) == /\ pc[self] = "na1"
             /\ allSeeded' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "na2"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, reseedRunning, running, bringups, 
                             task, prLock, resets, forces, dues, resetGen, 
                             esGen, swRet, good, rv, injRet, freshOut, freshES, 
                             goodSeed, outSince, tried, viol, stack, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

na2(self) == /\ pc[self] = "na2"
             /\ IF \E d \in Nodes : ~fs[d]
                   THEN /\ allSeeded' = FALSE
                   ELSE /\ TRUE
                        /\ UNCHANGED allSeeded
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, reseedRunning, running, bringups, 
                             task, prLock, resets, forces, dues, resetGen, 
                             esGen, swRet, good, rv, injRet, freshOut, freshES, 
                             goodSeed, outSince, tried, viol, ud, sd, lockMode, 
                             dfi, forced, thr, ep, eg, coll, collV, injd, 
                             seeded, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

noteAll(self) == na1(self) \/ na2(self)

se1(self) == /\ pc[self] = "se1"
             /\ IF lockMode[self]
                   THEN /\ lock[sd[self]] = NoProc
                   ELSE /\ TRUE
             /\ LET req == SeedReq(dfi[self], ~dfi[self] /\ sd[self] = PR) IN
                  LET dfi2 == dfi[self] \/ (lockMode[self] /\ ~fs[sd[self]]) IN
                    \E yv \in Collect(req):
                      \E ok \in InjOK:
                        LET stale == ResetEpoch /\ lockMode[self] /\ ep[self] # resetGen[sd[self]] IN
                          LET y == IF stale THEN 0 ELSE SumSet(yv, ES) IN
                            LET c == IF stale THEN 0 ELSE Min(coll[self] + y, FCap + Osr) IN
                              LET cv == IF stale THEN ZeroV ELSE AddV(collV[self], yv) IN
                                LET full == FullTest(dfi2, c, cv) /\ (sd[self] # PR \/ dfi2 \/ c >= req) IN
                                  LET again == forced[self] /\ ~(ok /\ full) /\ Delivered(yv) >= thr[self] IN
                                    LET seeded2 == seeded[self] \/ ok IN
                                      LET injd2 == IF ok THEN Min(injd[self] + y, FCap + Osr) ELSE injd[self] IN
                                        LET gv == IF (IF lockMode[self] THEN eg[self] ELSE esGen) < resetGen[sd[self]]
                                                  THEN ZeroV ELSE yv IN
                                          LET g == SumSet(gv, ES) IN
                                            /\ IF ok
                                                  THEN /\ viol' = (viol \cup CreditViol(sd[self], full, gv))
                                                       /\ goodSeed' = [goodSeed EXCEPT ![sd[self]] = IF full THEN Legit(sd[self], gv)
                                                                                                     ELSE fs[sd[self]] /\ goodSeed[sd[self]]]
                                                       /\ freshOut' = [freshOut EXCEPT ![sd[self]] = Min(freshOut[sd[self]] + g, FCap)]
                                                       /\ freshES' = [freshES EXCEPT ![sd[self]] = AddV(freshES[sd[self]], gv)]
                                                       /\ IF full \/ PartialResets
                                                             THEN /\ used' = [used EXCEPT ![sd[self]] = 0]
                                                             ELSE /\ TRUE
                                                                  /\ used' = used
                                                       /\ IF full /\ Legit(sd[self], gv)
                                                             THEN /\ outSince' = [outSince EXCEPT ![sd[self]] = 0]
                                                             ELSE /\ TRUE
                                                                  /\ UNCHANGED outSince
                                                       /\ due' = [due EXCEPT ![sd[self]] = FALSE]
                                                       /\ force' = [force EXCEPT ![sd[self]] = FALSE]
                                                       /\ IF ~fs[sd[self]] /\ full
                                                             THEN /\ fs' = [fs EXCEPT ![sd[self]] = TRUE]
                                                                  /\ initiated' = [initiated EXCEPT ![sd[self]] = TRUE]
                                                             ELSE /\ TRUE
                                                                  /\ UNCHANGED << fs, 
                                                                                  initiated >>
                                                  ELSE /\ force' = [force EXCEPT ![sd[self]] = TRUE]
                                                       /\ UNCHANGED << fs, 
                                                                       initiated, 
                                                                       used, 
                                                                       due, 
                                                                       freshOut, 
                                                                       freshES, 
                                                                       goodSeed, 
                                                                       outSince, 
                                                                       viol >>
                                            /\ IF again
                                                  THEN /\ dfi' = [dfi EXCEPT ![self] = dfi2]
                                                       /\ coll' = [coll EXCEPT ![self] = IF ok \/ CreditFailed \/ stale THEN c ELSE coll[self]]
                                                       /\ collV' = [collV EXCEPT ![self] = IF ok \/ CreditFailed \/ stale THEN cv ELSE collV[self]]
                                                       /\ seeded' = [seeded EXCEPT ![self] = seeded2]
                                                       /\ injd' = [injd EXCEPT ![self] = injd2]
                                                       /\ ep' = [ep EXCEPT ![self] = resetGen[sd[self]]]
                                                       /\ eg' = [eg EXCEPT ![self] = esGen]
                                                       /\ pc' = [pc EXCEPT ![self] = "se1"]
                                                       /\ UNCHANGED << operational, 
                                                                       injRet, 
                                                                       stack, 
                                                                       sd, 
                                                                       lockMode, 
                                                                       forced, 
                                                                       thr >>
                                                  ELSE /\ IF lockMode[self] /\ seeded2 /\ sd[self] = 0
                                                             THEN /\ pc' = [pc EXCEPT ![self] = "se2"]
                                                                  /\ UNCHANGED << operational, 
                                                                                  injRet, 
                                                                                  stack, 
                                                                                  sd, 
                                                                                  lockMode, 
                                                                                  dfi, 
                                                                                  forced, 
                                                                                  thr, 
                                                                                  ep, 
                                                                                  eg, 
                                                                                  coll, 
                                                                                  collV, 
                                                                                  injd, 
                                                                                  seeded >>
                                                             ELSE /\ IF seeded2 /\ sd[self] = 0 /\ (fs'[0] \/ (ok /\ full))
                                                                        THEN /\ operational' = TRUE
                                                                        ELSE /\ TRUE
                                                                             /\ UNCHANGED operational
                                                                  /\ IF sd[self] = PR
                                                                        THEN /\ injRet' = [injRet EXCEPT ![self] = injd2]
                                                                        ELSE /\ TRUE
                                                                             /\ UNCHANGED injRet
                                                                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                                  /\ coll' = [coll EXCEPT ![self] = Head(stack[self]).coll]
                                                                  /\ collV' = [collV EXCEPT ![self] = Head(stack[self]).collV]
                                                                  /\ injd' = [injd EXCEPT ![self] = Head(stack[self]).injd]
                                                                  /\ seeded' = [seeded EXCEPT ![self] = Head(stack[self]).seeded]
                                                                  /\ sd' = [sd EXCEPT ![self] = Head(stack[self]).sd]
                                                                  /\ lockMode' = [lockMode EXCEPT ![self] = Head(stack[self]).lockMode]
                                                                  /\ dfi' = [dfi EXCEPT ![self] = Head(stack[self]).dfi]
                                                                  /\ forced' = [forced EXCEPT ![self] = Head(stack[self]).forced]
                                                                  /\ thr' = [thr EXCEPT ![self] = Head(stack[self]).thr]
                                                                  /\ ep' = [ep EXCEPT ![self] = Head(stack[self]).ep]
                                                                  /\ eg' = [eg EXCEPT ![self] = Head(stack[self]).eg]
                                                                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << lock, seedLock, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, tried, ud, sdd, 
                             rsd, rep, reg, swForce, swWait, i, sel, busy, rd, 
                             rnb, gd, gnb, glen, processed, exhausted, stop, 
                             uns, spr, snb, slen, pick, snb2, od, kind, n, 
                             done, ai >>

se2(self) == /\ pc[self] = "se2"
             /\ lock[0] = NoProc
             /\ IF fs[0]
                   THEN /\ operational' = TRUE
                   ELSE /\ TRUE
                        /\ UNCHANGED operational
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ coll' = [coll EXCEPT ![self] = Head(stack[self]).coll]
             /\ collV' = [collV EXCEPT ![self] = Head(stack[self]).collV]
             /\ injd' = [injd EXCEPT ![self] = Head(stack[self]).injd]
             /\ seeded' = [seeded EXCEPT ![self] = Head(stack[self]).seeded]
             /\ sd' = [sd EXCEPT ![self] = Head(stack[self]).sd]
             /\ lockMode' = [lockMode EXCEPT ![self] = Head(stack[self]).lockMode]
             /\ dfi' = [dfi EXCEPT ![self] = Head(stack[self]).dfi]
             /\ forced' = [forced EXCEPT ![self] = Head(stack[self]).forced]
             /\ thr' = [thr EXCEPT ![self] = Head(stack[self]).thr]
             /\ ep' = [ep EXCEPT ![self] = Head(stack[self]).ep]
             /\ eg' = [eg EXCEPT ![self] = Head(stack[self]).eg]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             allSeeded, reseedRunning, running, bringups, task, 
                             prLock, resets, forces, dues, resetGen, esGen, 
                             swRet, good, rv, injRet, freshOut, freshES, 
                             goodSeed, outSince, tried, viol, ud, sdd, rsd, 
                             rep, reg, swForce, swWait, i, sel, busy, rd, rnb, 
                             gd, gnb, glen, processed, exhausted, stop, uns, 
                             spr, snb, slen, pick, snb2, od, kind, n, done, ai >>

seedEs(self) == se1(self) \/ se2(self)

sdA(self) == /\ pc[self] = "sdA"
             /\ lock[sdd[self]] = NoProc
             /\ lock' = [lock EXCEPT ![sdd[self]] = self]
             /\ /\ dfi' = [dfi EXCEPT ![self] = Dfi(sdd[self])]
                /\ eg' = [eg EXCEPT ![self] = 0]
                /\ ep' = [ep EXCEPT ![self] = 0]
                /\ forced' = [forced EXCEPT ![self] = force[sdd[self]] \/ Dfi(sdd[self])]
                /\ lockMode' = [lockMode EXCEPT ![self] = FALSE]
                /\ sd' = [sd EXCEPT ![self] = sdd[self]]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedEs",
                                                         pc        |->  "sdB",
                                                         coll      |->  coll[self],
                                                         collV     |->  collV[self],
                                                         injd      |->  injd[self],
                                                         seeded    |->  seeded[self],
                                                         sd        |->  sd[self],
                                                         lockMode  |->  lockMode[self],
                                                         dfi       |->  dfi[self],
                                                         forced    |->  forced[self],
                                                         thr       |->  thr[self],
                                                         ep        |->  ep[self],
                                                         eg        |->  eg[self] ] >>
                                                     \o stack[self]]
                /\ thr' = [thr EXCEPT ![self] = Thr(sdd[self])]
             /\ coll' = [coll EXCEPT ![self] = 0]
             /\ collV' = [collV EXCEPT ![self] = ZeroV]
             /\ injd' = [injd EXCEPT ![self] = 0]
             /\ seeded' = [seeded EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "se1"]
             /\ UNCHANGED << fs, force, initiated, used, due, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

sdB(self) == /\ pc[self] = "sdB"
             /\ lock' = [lock EXCEPT ![sdd[self]] = NoProc]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ sdd' = [sdd EXCEPT ![self] = Head(stack[self]).sdd]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, rsd, rep, reg, swForce, 
                             swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, kind, n, done, ai >>

seed(self) == sdA(self) \/ sdB(self)

rs0(self) == /\ pc[self] = "rs0"
             /\ IF PerRequest /\ self \in Req
                   THEN /\ tried' = [tried EXCEPT ![self] = TRUE]
                   ELSE /\ TRUE
                        /\ tried' = tried
             /\ IF rsd[self] = PR \/ ~fs[rsd[self]]
                   THEN /\ /\ reg' = [reg EXCEPT ![self] = Head(stack[self]).reg]
                           /\ rep' = [rep EXCEPT ![self] = Head(stack[self]).rep]
                           /\ sdd' = [sdd EXCEPT ![self] = rsd[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seed",
                                                                    pc        |->  Head(stack[self]).pc,
                                                                    sdd       |->  sdd[self] ] >>
                                                                \o Tail(stack[self])]
                        /\ pc' = [pc EXCEPT ![self] = "sdA"]
                        /\ UNCHANGED << force, sd, lockMode, dfi, forced, thr, 
                                        ep, eg, coll, collV, injd, seeded >>
                   ELSE /\ IF Budget(rsd[self], used[rsd[self]]) = 0
                              THEN /\ force' = [force EXCEPT ![rsd[self]] = TRUE]
                                   /\ /\ dfi' = [dfi EXCEPT ![self] = Dfi(rsd[self])]
                                      /\ eg' = [eg EXCEPT ![self] = esGen]
                                      /\ ep' = [ep EXCEPT ![self] = resetGen[rsd[self]]]
                                      /\ forced' = [forced EXCEPT ![self] = TRUE]
                                      /\ lockMode' = [lockMode EXCEPT ![self] = TRUE]
                                      /\ reg' = [reg EXCEPT ![self] = Head(stack[self]).reg]
                                      /\ rep' = [rep EXCEPT ![self] = Head(stack[self]).rep]
                                      /\ sd' = [sd EXCEPT ![self] = rsd[self]]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedEs",
                                                                               pc        |->  Head(stack[self]).pc,
                                                                               coll      |->  coll[self],
                                                                               collV     |->  collV[self],
                                                                               injd      |->  injd[self],
                                                                               seeded    |->  seeded[self],
                                                                               sd        |->  sd[self],
                                                                               lockMode  |->  lockMode[self],
                                                                               dfi       |->  dfi[self],
                                                                               forced    |->  forced[self],
                                                                               thr       |->  thr[self],
                                                                               ep        |->  ep[self],
                                                                               eg        |->  eg[self] ] >>
                                                                           \o Tail(stack[self])]
                                      /\ thr' = [thr EXCEPT ![self] = Thr(rsd[self])]
                                   /\ coll' = [coll EXCEPT ![self] = 0]
                                   /\ collV' = [collV EXCEPT ![self] = ZeroV]
                                   /\ injd' = [injd EXCEPT ![self] = 0]
                                   /\ seeded' = [seeded EXCEPT ![self] = FALSE]
                                   /\ pc' = [pc EXCEPT ![self] = "se1"]
                              ELSE /\ rep' = [rep EXCEPT ![self] = resetGen[rsd[self]]]
                                   /\ reg' = [reg EXCEPT ![self] = esGen]
                                   /\ pc' = [pc EXCEPT ![self] = "rs1"]
                                   /\ UNCHANGED << force, stack, sd, lockMode, 
                                                   dfi, forced, thr, ep, eg, 
                                                   coll, collV, injd, seeded >>
                        /\ sdd' = sdd
             /\ UNCHANGED << fs, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, viol, ud, 
                             rsd, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done, ai >>

rs1(self) == /\ pc[self] = "rs1"
             /\ lock[rsd[self]] = NoProc
             /\ \E yv \in Collect(SS):
                  \E ok \in InjOK:
                    LET y == SumSet(yv, ES) IN
                      LET stale == ResetEpoch /\ rep[self] # resetGen[rsd[self]] IN
                        LET full == ~stale /\ FullTest(~fs[rsd[self]], y, yv) IN
                          LET gv == IF reg[self] < resetGen[rsd[self]] THEN ZeroV ELSE yv IN
                            LET g == SumSet(gv, ES) IN
                              IF ok
                                 THEN /\ viol' = (viol \cup CreditViol(rsd[self], full, gv))
                                      /\ goodSeed' = [goodSeed EXCEPT ![rsd[self]] = IF full THEN Legit(rsd[self], gv)
                                                                                     ELSE fs[rsd[self]] /\ goodSeed[rsd[self]]]
                                      /\ freshOut' = [freshOut EXCEPT ![rsd[self]] = Min(freshOut[rsd[self]] + g, FCap)]
                                      /\ freshES' = [freshES EXCEPT ![rsd[self]] = AddV(freshES[rsd[self]], gv)]
                                      /\ IF full \/ PartialResets
                                            THEN /\ used' = [used EXCEPT ![rsd[self]] = 0]
                                            ELSE /\ TRUE
                                                 /\ used' = used
                                      /\ IF full /\ Legit(rsd[self], gv)
                                            THEN /\ outSince' = [outSince EXCEPT ![rsd[self]] = 0]
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED outSince
                                      /\ due' = [due EXCEPT ![rsd[self]] = FALSE]
                                      /\ force' = [force EXCEPT ![rsd[self]] = FALSE]
                                      /\ IF ~fs[rsd[self]] /\ full
                                            THEN /\ fs' = [fs EXCEPT ![rsd[self]] = TRUE]
                                                 /\ initiated' = [initiated EXCEPT ![rsd[self]] = TRUE]
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED << fs, initiated >>
                                      /\ IF rsd[self] = 0 /\ (fs'[rsd[self]] \/ full)
                                            THEN /\ operational' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED operational
                                 ELSE /\ force' = [force EXCEPT ![rsd[self]] = TRUE]
                                      /\ UNCHANGED << fs, initiated, used, due, 
                                                      operational, freshOut, 
                                                      freshES, goodSeed, 
                                                      outSince, viol >>
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ rep' = [rep EXCEPT ![self] = Head(stack[self]).rep]
             /\ reg' = [reg EXCEPT ![self] = Head(stack[self]).reg]
             /\ rsd' = [rsd EXCEPT ![self] = Head(stack[self]).rsd]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << lock, seedLock, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, tried, 
                             ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                             collV, injd, seeded, sdd, swForce, swWait, i, sel, 
                             busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

reseedLocked(self) == rs0(self) \/ rs1(self)

sw1(self) == /\ pc[self] = "sw1"
             /\ IF i[self] < NN
                   THEN /\ IF fs[i[self]]
                              THEN /\ i' = [i EXCEPT ![self] = i[self] + 1]
                                   /\ UNCHANGED << seedLock, sel, busy >>
                              ELSE /\ IF seedLock[i[self]] # NoProc
                                         THEN /\ IF busy[self] = NoTask
                                                    THEN /\ busy' = [busy EXCEPT ![self] = i[self]]
                                                    ELSE /\ TRUE
                                                         /\ busy' = busy
                                              /\ i' = [i EXCEPT ![self] = i[self] + 1]
                                              /\ UNCHANGED << seedLock, sel >>
                                         ELSE /\ seedLock' = [seedLock EXCEPT ![i[self]] = self]
                                              /\ sel' = [sel EXCEPT ![self] = i[self]]
                                              /\ i' = [i EXCEPT ![self] = NN]
                                              /\ busy' = busy
                        /\ pc' = [pc EXCEPT ![self] = "sw1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "sw2"]
                        /\ UNCHANGED << seedLock, i, sel, busy >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, rd, rnb, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, kind, n, done, ai >>

sw2(self) == /\ pc[self] = "sw2"
             /\ IF sel[self] # NoTask
                   THEN /\ IF ~fs[sel[self]]
                              THEN /\ IF swForce[self]
                                         THEN /\ force' = [force EXCEPT ![sel[self]] = TRUE]
                                         ELSE /\ TRUE
                                              /\ force' = force
                                   /\ /\ sdd' = [sdd EXCEPT ![self] = sel[self]]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seed",
                                                                               pc        |->  "sw3",
                                                                               sdd       |->  sdd[self] ] >>
                                                                           \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "sdA"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "sw3"]
                                   /\ UNCHANGED << force, stack, sdd >>
                        /\ UNCHANGED << seedLock, swRet, swForce, swWait, i, 
                                        sel, busy >>
                   ELSE /\ IF busy[self] # NoTask /\ swWait[self]
                              THEN /\ seedLock[busy[self]] = NoProc
                                   /\ seedLock' = [seedLock EXCEPT ![busy[self]] = self]
                                   /\ sel' = [sel EXCEPT ![self] = busy[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "sw2"]
                                   /\ UNCHANGED << swRet, stack, swForce, 
                                                   swWait, i, busy >>
                              ELSE /\ IF busy[self] # NoTask
                                         THEN /\ IF self \in AdminProcs
                                                    THEN /\ swRet' = [swRet EXCEPT ![self] = FALSE]
                                                    ELSE /\ TRUE
                                                         /\ swRet' = swRet
                                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                              /\ i' = [i EXCEPT ![self] = Head(stack[self]).i]
                                              /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
                                              /\ busy' = [busy EXCEPT ![self] = Head(stack[self]).busy]
                                              /\ swForce' = [swForce EXCEPT ![self] = Head(stack[self]).swForce]
                                              /\ swWait' = [swWait EXCEPT ![self] = Head(stack[self]).swWait]
                                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                         ELSE /\ IF self \in AdminProcs
                                                    THEN /\ swRet' = [swRet EXCEPT ![self] = TRUE]
                                                    ELSE /\ TRUE
                                                         /\ swRet' = swRet
                                              /\ /\ busy' = [busy EXCEPT ![self] = Head(stack[self]).busy]
                                                 /\ i' = [i EXCEPT ![self] = Head(stack[self]).i]
                                                 /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
                                                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "noteAll",
                                                                                          pc        |->  Head(stack[self]).pc ] >>
                                                                                      \o Tail(stack[self])]
                                              /\ pc' = [pc EXCEPT ![self] = "na1"]
                                              /\ UNCHANGED << swForce, swWait >>
                                   /\ UNCHANGED seedLock
                        /\ UNCHANGED << force, sdd >>
             /\ UNCHANGED << fs, initiated, used, due, lock, operational, 
                             allSeeded, reseedRunning, running, bringups, task, 
                             prLock, resets, forces, dues, resetGen, esGen, 
                             good, rv, injRet, freshOut, freshES, goodSeed, 
                             outSince, tried, viol, ud, sd, lockMode, dfi, 
                             forced, thr, ep, eg, coll, collV, injd, seeded, 
                             rsd, rep, reg, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

sw3(self) == /\ pc[self] = "sw3"
             /\ seedLock' = [seedLock EXCEPT ![sel[self]] = NoProc]
             /\ IF self \in AdminProcs
                   THEN /\ swRet' = [swRet EXCEPT ![self] = fs[sel[self]]]
                   ELSE /\ TRUE
                        /\ swRet' = swRet
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ i' = [i EXCEPT ![self] = Head(stack[self]).i]
             /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
             /\ busy' = [busy EXCEPT ![self] = Head(stack[self]).busy]
             /\ swForce' = [swForce EXCEPT ![self] = Head(stack[self]).swForce]
             /\ swWait' = [swWait EXCEPT ![self] = Head(stack[self]).swWait]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, good, rv, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done, ai >>

seedWork(self) == sw1(self) \/ sw2(self) \/ sw3(self)

swt(self) == /\ pc[self] = "swt"
             /\ \/ /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWork",
                                                               pc        |->  Head(stack[self]).pc,
                                                               i         |->  i[self],
                                                               sel       |->  sel[self],
                                                               busy      |->  busy[self],
                                                               swForce   |->  swForce[self],
                                                               swWait    |->  swWait[self] ] >>
                                                           \o Tail(stack[self])]
                      /\ swForce' = [swForce EXCEPT ![self] = FALSE]
                      /\ swWait' = [swWait EXCEPT ![self] = FALSE]
                   /\ i' = [i EXCEPT ![self] = 0]
                   /\ sel' = [sel EXCEPT ![self] = NoTask]
                   /\ busy' = [busy EXCEPT ![self] = NoTask]
                   /\ pc' = [pc EXCEPT ![self] = "sw1"]
                \/ /\ ~good
                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   /\ UNCHANGED <<swForce, swWait, i, sel, busy>>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, rd, 
                             rnb, gd, gnb, glen, processed, exhausted, stop, 
                             uns, spr, snb, slen, pick, snb2, od, kind, n, 
                             done, ai >>

seedWorkTry(self) == swt(self)

ff(self) == /\ pc[self] = "ff"
            /\ IF allSeeded
                  THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << swForce, swWait, i, sel, busy >>
                  ELSE /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWork",
                                                                   pc        |->  Head(stack[self]).pc,
                                                                   i         |->  i[self],
                                                                   sel       |->  sel[self],
                                                                   busy      |->  busy[self],
                                                                   swForce   |->  swForce[self],
                                                                   swWait    |->  swWait[self] ] >>
                                                               \o Tail(stack[self])]
                          /\ swForce' = [swForce EXCEPT ![self] = TRUE]
                          /\ swWait' = [swWait EXCEPT ![self] = TRUE]
                       /\ i' = [i EXCEPT ![self] = 0]
                       /\ sel' = [sel EXCEPT ![self] = NoTask]
                       /\ busy' = [busy EXCEPT ![self] = NoTask]
                       /\ pc' = [pc EXCEPT ![self] = "sw1"]
            /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                            operational, allSeeded, reseedRunning, running, 
                            bringups, task, prLock, resets, forces, dues, 
                            resetGen, esGen, swRet, good, rv, injRet, freshOut, 
                            freshES, goodSeed, outSince, tried, viol, ud, sd, 
                            lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                            injd, seeded, sdd, rsd, rep, reg, rd, rnb, gd, gnb, 
                            glen, processed, exhausted, stop, uns, spr, snb, 
                            slen, pick, snb2, od, kind, n, done, ai >>

forceFS(self) == ff(self)

fa0(self) == /\ pc[self] = "fa0"
             /\ IF allSeeded
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "fa1"]
                        /\ stack' = stack
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, snb2, od, kind, n, done, ai >>

fa1(self) == /\ pc[self] = "fa1"
             /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWork",
                                                         pc        |->  "fa2",
                                                         i         |->  i[self],
                                                         sel       |->  sel[self],
                                                         busy      |->  busy[self],
                                                         swForce   |->  swForce[self],
                                                         swWait    |->  swWait[self] ] >>
                                                     \o stack[self]]
                /\ swForce' = [swForce EXCEPT ![self] = TRUE]
                /\ swWait' = [swWait EXCEPT ![self] = TRUE]
             /\ i' = [i EXCEPT ![self] = 0]
             /\ sel' = [sel EXCEPT ![self] = NoTask]
             /\ busy' = [busy EXCEPT ![self] = NoTask]
             /\ pc' = [pc EXCEPT ![self] = "sw1"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, rd, 
                             rnb, gd, gnb, glen, processed, exhausted, stop, 
                             uns, spr, snb, slen, pick, snb2, od, kind, n, 
                             done, ai >>

fa2(self) == /\ pc[self] = "fa2"
             /\ \E avail \in IF good THEN {TRUE} ELSE BOOLEAN:
                  IF swRet[self] /\ ~allSeeded /\ avail
                     THEN /\ pc' = [pc EXCEPT ![self] = "fa1"]
                          /\ stack' = stack
                     ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                          /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, snb2, od, kind, n, done, ai >>

forceAll(self) == fa0(self) \/ fa1(self) \/ fa2(self)

gr0(self) == /\ pc[self] = "gr0"
             /\ IF ~MustReseed(rd[self])
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ rd' = [rd EXCEPT ![self] = Head(stack[self]).rd]
                        /\ rnb' = [rnb EXCEPT ![self] = Head(stack[self]).rnb]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << force, seedLock, rsd, rep, reg >>
                   ELSE /\ IF rd[self] # 0 /\ Worker /\ ~PerRequest
                              THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ rd' = [rd EXCEPT ![self] = Head(stack[self]).rd]
                                   /\ rnb' = [rnb EXCEPT ![self] = Head(stack[self]).rnb]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                   /\ UNCHANGED << force, seedLock, rsd, rep, 
                                                   reg >>
                              ELSE /\ IF rnb[self]
                                         THEN /\ \/ /\ seedLock[rd[self]] = NoProc
                                                    /\ seedLock' = [seedLock EXCEPT ![rd[self]] = self]
                                                    /\ IF MustReseed(rd[self])
                                                          THEN /\ /\ rsd' = [rsd EXCEPT ![self] = rd[self]]
                                                                  /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reseedLocked",
                                                                                                           pc        |->  "gr1",
                                                                                                           rep       |->  rep[self],
                                                                                                           reg       |->  reg[self],
                                                                                                           rsd       |->  rsd[self] ] >>
                                                                                                       \o stack[self]]
                                                               /\ rep' = [rep EXCEPT ![self] = 0]
                                                               /\ reg' = [reg EXCEPT ![self] = 0]
                                                               /\ pc' = [pc EXCEPT ![self] = "rs0"]
                                                          ELSE /\ pc' = [pc EXCEPT ![self] = "gr1"]
                                                               /\ UNCHANGED << stack, 
                                                                               rsd, 
                                                                               rep, 
                                                                               reg >>
                                                    /\ UNCHANGED <<force, rd, rnb>>
                                                 \/ /\ seedLock[rd[self]] # NoProc \/ ~good
                                                    /\ force' = [force EXCEPT ![rd[self]] = TRUE]
                                                    /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                    /\ rd' = [rd EXCEPT ![self] = Head(stack[self]).rd]
                                                    /\ rnb' = [rnb EXCEPT ![self] = Head(stack[self]).rnb]
                                                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                    /\ UNCHANGED <<seedLock, rsd, rep, reg>>
                                         ELSE /\ seedLock[rd[self]] = NoProc
                                              /\ seedLock' = [seedLock EXCEPT ![rd[self]] = self]
                                              /\ IF MustReseed(rd[self])
                                                    THEN /\ /\ rsd' = [rsd EXCEPT ![self] = rd[self]]
                                                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reseedLocked",
                                                                                                     pc        |->  "gr1",
                                                                                                     rep       |->  rep[self],
                                                                                                     reg       |->  reg[self],
                                                                                                     rsd       |->  rsd[self] ] >>
                                                                                                 \o stack[self]]
                                                         /\ rep' = [rep EXCEPT ![self] = 0]
                                                         /\ reg' = [reg EXCEPT ![self] = 0]
                                                         /\ pc' = [pc EXCEPT ![self] = "rs0"]
                                                    ELSE /\ pc' = [pc EXCEPT ![self] = "gr1"]
                                                         /\ UNCHANGED << stack, 
                                                                         rsd, 
                                                                         rep, 
                                                                         reg >>
                                              /\ UNCHANGED << force, rd, rnb >>
             /\ UNCHANGED << fs, initiated, used, due, lock, operational, 
                             allSeeded, reseedRunning, running, bringups, task, 
                             prLock, resets, forces, dues, resetGen, esGen, 
                             swRet, good, rv, injRet, freshOut, freshES, 
                             goodSeed, outSince, tried, viol, ud, sd, lockMode, 
                             dfi, forced, thr, ep, eg, coll, collV, injd, 
                             seeded, sdd, swForce, swWait, i, sel, busy, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done, ai >>

gr1(self) == /\ pc[self] = "gr1"
             /\ seedLock' = [seedLock EXCEPT ![rd[self]] = NoProc]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ rd' = [rd EXCEPT ![self] = Head(stack[self]).rd]
             /\ rnb' = [rnb EXCEPT ![self] = Head(stack[self]).rnb]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, kind, n, done, ai >>

getReseed(self) == gr0(self) \/ gr1(self)

dg0(self) == /\ pc[self] = "dg0"
             /\ IF ~operational
                   THEN /\ rv' = [rv EXCEPT ![self] = -1]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ processed' = [processed EXCEPT ![self] = Head(stack[self]).processed]
                        /\ exhausted' = [exhausted EXCEPT ![self] = Head(stack[self]).exhausted]
                        /\ stop' = [stop EXCEPT ![self] = Head(stack[self]).stop]
                        /\ uns' = [uns EXCEPT ![self] = Head(stack[self]).uns]
                        /\ gd' = [gd EXCEPT ![self] = Head(stack[self]).gd]
                        /\ gnb' = [gnb EXCEPT ![self] = Head(stack[self]).gnb]
                        /\ glen' = [glen EXCEPT ![self] = Head(stack[self]).glen]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "dg1"]
                        /\ UNCHANGED << rv, stack, gd, gnb, glen, processed, 
                                        exhausted, stop, uns >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

dg1(self) == /\ pc[self] = "dg1"
             /\ IF glen[self] > 0
                   THEN /\ IF gd[self] = PR
                              THEN /\ IF gnb[self] /\ lock[PR] # NoProc
                                         THEN /\ pc' = [pc EXCEPT ![self] = "dg9"]
                                              /\ UNCHANGED << lock, stack, sd, 
                                                              lockMode, dfi, 
                                                              forced, thr, ep, 
                                                              eg, coll, collV, 
                                                              injd, seeded >>
                                         ELSE /\ lock[PR] = NoProc
                                              /\ lock' = [lock EXCEPT ![PR] = self]
                                              /\ /\ dfi' = [dfi EXCEPT ![self] = Dfi(PR)]
                                                 /\ eg' = [eg EXCEPT ![self] = 0]
                                                 /\ ep' = [ep EXCEPT ![self] = 0]
                                                 /\ forced' = [forced EXCEPT ![self] = force[PR] \/ Dfi(PR)]
                                                 /\ lockMode' = [lockMode EXCEPT ![self] = FALSE]
                                                 /\ sd' = [sd EXCEPT ![self] = PR]
                                                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedEs",
                                                                                          pc        |->  "dgP",
                                                                                          coll      |->  coll[self],
                                                                                          collV     |->  collV[self],
                                                                                          injd      |->  injd[self],
                                                                                          seeded    |->  seeded[self],
                                                                                          sd        |->  sd[self],
                                                                                          lockMode  |->  lockMode[self],
                                                                                          dfi       |->  dfi[self],
                                                                                          forced    |->  forced[self],
                                                                                          thr       |->  thr[self],
                                                                                          ep        |->  ep[self],
                                                                                          eg        |->  eg[self] ] >>
                                                                                      \o stack[self]]
                                                 /\ thr' = [thr EXCEPT ![self] = Thr(PR)]
                                              /\ coll' = [coll EXCEPT ![self] = 0]
                                              /\ collV' = [collV EXCEPT ![self] = ZeroV]
                                              /\ injd' = [injd EXCEPT ![self] = 0]
                                              /\ seeded' = [seeded EXCEPT ![self] = FALSE]
                                              /\ pc' = [pc EXCEPT ![self] = "se1"]
                                   /\ UNCHANGED << rd, rnb >>
                              ELSE /\ /\ rd' = [rd EXCEPT ![self] = gd[self]]
                                      /\ rnb' = [rnb EXCEPT ![self] = gnb[self]]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getReseed",
                                                                               pc        |->  "dgN",
                                                                               rd        |->  rd[self],
                                                                               rnb       |->  rnb[self] ] >>
                                                                           \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "gr0"]
                                   /\ UNCHANGED << lock, sd, lockMode, dfi, 
                                                   forced, thr, ep, eg, coll, 
                                                   collV, injd, seeded >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "dg9"]
                        /\ UNCHANGED << lock, stack, sd, lockMode, dfi, forced, 
                                        thr, ep, eg, coll, collV, injd, seeded, 
                                        rd, rnb >>
             /\ UNCHANGED << fs, force, initiated, used, due, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, gd, gnb, glen, processed, exhausted, 
                             stop, uns, spr, snb, slen, pick, snb2, od, kind, 
                             n, done, ai >>

dgP(self) == /\ pc[self] = "dgP"
             /\ LET t == IF PRWaitInit /\ ~initiated[PR] THEN 0
                         ELSE Min(Min(glen[self], injRet[self] - Osr), SS) IN
                  /\ IF t <= 0
                        THEN /\ stop' = [stop EXCEPT ![self] = TRUE]
                             /\ UNCHANGED << fs, freshOut, freshES, goodSeed, 
                                             viol, glen, processed >>
                        ELSE /\ viol' =     viol
                                        \cup (IF t > freshOut[PR] - Osr
                                              THEN {"PROutput"} ELSE {})
                                        \cup (IF ~initiated[PR] THEN {"PRInitiated"} ELSE {})
                             /\ freshOut' = [freshOut EXCEPT ![PR] = 0]
                             /\ freshES' = [freshES EXCEPT ![PR] = ZeroV]
                             /\ fs' = [fs EXCEPT ![PR] = FALSE]
                             /\ goodSeed' = [goodSeed EXCEPT ![PR] = FALSE]
                             /\ processed' = [processed EXCEPT ![self] = processed[self] + t]
                             /\ glen' = [glen EXCEPT ![self] = glen[self] - t]
                             /\ stop' = [stop EXCEPT ![self] = FALSE]
                  /\ lock' = [lock EXCEPT ![PR] = NoProc]
                  /\ injRet' = [injRet EXCEPT ![self] = 0]
             /\ IF stop'[self]
                   THEN /\ pc' = [pc EXCEPT ![self] = "dg9"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "dg1"]
             /\ UNCHANGED << force, initiated, used, due, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, outSince, tried, 
                             stack, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             exhausted, uns, spr, snb, slen, pick, snb2, od, 
                             kind, n, done, ai >>

dgN(self) == /\ pc[self] = "dgN"
             /\ lock[gd[self]] = NoProc
             /\ LET f == fs[gd[self]] IN
                  LET b == Budget(gd[self], used[gd[self]]) IN
                    LET t == IF ~f THEN 0
                             ELSE IF gd[self] = 0 THEN Min(glen[self], b)
                             ELSE IF b = 0 THEN 0 ELSE glen[self] IN
                      LET dis == Disable(gd[self]) IN
                        LET gen == f /\ t > 0 /\ ~dis IN
                          LET nu == IF gen THEN UsedAfter(used[gd[self]], t) ELSE used[gd[self]] IN
                            LET spent == gen /\ gd[self] # 0 /\ Budget(gd[self], nu) = 0 IN
                              LET u == \/ f /\ ~gen /\ (IF gd[self] = 0 THEN dis
                                                        ELSE (b > 0 \/ ~Worker))
                                       \/ spent /\ ~Worker IN
                                /\ IF gen
                                      THEN /\ viol' =     viol
                                                      \cup (IF Budgeted /\ gd[self] # 0 /\ used[gd[self]] >= MaxBits
                                                            THEN {"ChunkPastMax"} ELSE {})
                                                      \cup (IF Budgeted /\ gd[self] = 0
                                                               /\ nu > Min(MaxBits, ThreshBits)
                                                            THEN {"InitPastBudget"} ELSE {})
                                                      \cup (IF ~goodSeed[gd[self]]
                                                            THEN {"OutputUnseeded"} ELSE {})
                                                      \cup (IF PerRequest /\ ~gnb[self] /\ ~tried[self]
                                                            THEN {"NoReseed"} ELSE {})
                                           /\ used' = [used EXCEPT ![gd[self]] = nu]
                                           /\ outSince' = [outSince EXCEPT ![gd[self]] = IF Budgeted
                                                                                         THEN Min(outSince[gd[self]] + t, UCap) ELSE 0]
                                           /\ freshOut' = [freshOut EXCEPT ![gd[self]] = 0]
                                           /\ freshES' = [freshES EXCEPT ![gd[self]] = ZeroV]
                                           /\ processed' = [processed EXCEPT ![self] = processed[self] + t]
                                           /\ glen' = [glen EXCEPT ![self] = glen[self] - t]
                                      ELSE /\ TRUE
                                           /\ UNCHANGED << used, freshOut, 
                                                           freshES, outSince, 
                                                           viol, glen, 
                                                           processed >>
                                /\ exhausted' = [exhausted EXCEPT ![self] = exhausted[self] \/ (f /\ ~gen) \/ spent]
                                /\ stop' = [stop EXCEPT ![self] = ~gen]
                                /\ uns' = [uns EXCEPT ![self] = u]
                                /\ IF u
                                      THEN /\ lock' = [lock EXCEPT ![gd[self]] = self]
                                      ELSE /\ TRUE
                                           /\ lock' = lock
                                /\ IF PerRequest
                                      THEN /\ tried' = [tried EXCEPT ![self] = FALSE]
                                      ELSE /\ TRUE
                                           /\ tried' = tried
             /\ IF uns'[self]
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "unset",
                                                                    pc        |->  "dgU",
                                                                    ud        |->  ud[self] ] >>
                                                                \o stack[self]]
                           /\ ud' = [ud EXCEPT ![self] = gd[self]]
                        /\ pc' = [pc EXCEPT ![self] = "us1"]
                   ELSE /\ IF stop'[self]
                              THEN /\ pc' = [pc EXCEPT ![self] = "dg9"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "dg1"]
                        /\ UNCHANGED << stack, ud >>
             /\ UNCHANGED << fs, force, initiated, due, seedLock, operational, 
                             allSeeded, reseedRunning, running, bringups, task, 
                             prLock, resets, forces, dues, resetGen, esGen, 
                             swRet, good, rv, injRet, goodSeed, sd, lockMode, 
                             dfi, forced, thr, ep, eg, coll, collV, injd, 
                             seeded, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, rd, rnb, gd, gnb, spr, snb, slen, pick, 
                             snb2, od, kind, n, done, ai >>

dgU(self) == /\ pc[self] = "dgU"
             /\ lock' = [lock EXCEPT ![gd[self]] = NoProc]
             /\ IF stop[self]
                   THEN /\ pc' = [pc EXCEPT ![self] = "dg9"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "dg1"]
             /\ UNCHANGED << fs, force, initiated, used, due, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done, ai >>

dg9(self) == /\ pc[self] = "dg9"
             /\ IF exhausted[self] /\ ~Worker
                   THEN /\ IF gnb[self]
                              THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWorkTry",
                                                                            pc        |->  "dgR" ] >>
                                                                        \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "swt"]
                              ELSE /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "forceFS",
                                                                            pc        |->  "dgR" ] >>
                                                                        \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "ff"]
                        /\ UNCHANGED << rv, gd, gnb, glen, processed, 
                                        exhausted, stop, uns >>
                   ELSE /\ rv' = [rv EXCEPT ![self] = processed[self]]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ processed' = [processed EXCEPT ![self] = Head(stack[self]).processed]
                        /\ exhausted' = [exhausted EXCEPT ![self] = Head(stack[self]).exhausted]
                        /\ stop' = [stop EXCEPT ![self] = Head(stack[self]).stop]
                        /\ uns' = [uns EXCEPT ![self] = Head(stack[self]).uns]
                        /\ gd' = [gd EXCEPT ![self] = Head(stack[self]).gd]
                        /\ gnb' = [gnb EXCEPT ![self] = Head(stack[self]).gnb]
                        /\ glen' = [glen EXCEPT ![self] = Head(stack[self]).glen]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

dgR(self) == /\ pc[self] = "dgR"
             /\ rv' = [rv EXCEPT ![self] = processed[self]]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ processed' = [processed EXCEPT ![self] = Head(stack[self]).processed]
             /\ exhausted' = [exhausted EXCEPT ![self] = Head(stack[self]).exhausted]
             /\ stop' = [stop EXCEPT ![self] = Head(stack[self]).stop]
             /\ uns' = [uns EXCEPT ![self] = Head(stack[self]).uns]
             /\ gd' = [gd EXCEPT ![self] = Head(stack[self]).gd]
             /\ gnb' = [gnb EXCEPT ![self] = Head(stack[self]).gnb]
             /\ glen' = [glen EXCEPT ![self] = Head(stack[self]).glen]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

drngGet(self) == dg0(self) \/ dg1(self) \/ dgP(self) \/ dgN(self)
                    \/ dgU(self) \/ dg9(self) \/ dgR(self)

gs0(self) == /\ pc[self] = "gs0"
             /\ IF spr[self]
                   THEN /\ pick' = [pick EXCEPT ![self] = PR]
                   ELSE /\ LET c == {j \in 1..NN-1 :
                                     lock[j] = NoProc /\ fs[j] /\ Budget(j, used[j]) > 0} IN
                             \E j \in IF c = {} THEN {0} ELSE c:
                               pick' = [pick EXCEPT ![self] = j]
             /\ pc' = [pc EXCEPT ![self] = "gs1"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, snb2, od, kind, n, done, ai >>

gs1(self) == /\ pc[self] = "gs1"
             /\ /\ gd' = [gd EXCEPT ![self] = pick[self]]
                /\ glen' = [glen EXCEPT ![self] = slen[self]]
                /\ gnb' = [gnb EXCEPT ![self] = snb[self]]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "drngGet",
                                                         pc        |->  "gs2",
                                                         processed |->  processed[self],
                                                         exhausted |->  exhausted[self],
                                                         stop      |->  stop[self],
                                                         uns       |->  uns[self],
                                                         gd        |->  gd[self],
                                                         gnb       |->  gnb[self],
                                                         glen      |->  glen[self] ] >>
                                                     \o stack[self]]
             /\ processed' = [processed EXCEPT ![self] = 0]
             /\ exhausted' = [exhausted EXCEPT ![self] = FALSE]
             /\ stop' = [stop EXCEPT ![self] = FALSE]
             /\ uns' = [uns EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "dg0"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, spr, snb, 
                             slen, pick, snb2, od, kind, n, done, ai >>

gs2(self) == /\ pc[self] = "gs2"
             /\ IF ~spr[self] /\ pick[self] # 0 /\ rv[self] = 0
                   THEN /\ /\ gd' = [gd EXCEPT ![self] = 0]
                           /\ glen' = [glen EXCEPT ![self] = slen[self]]
                           /\ gnb' = [gnb EXCEPT ![self] = snb[self]]
                           /\ pick' = [pick EXCEPT ![self] = Head(stack[self]).pick]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "drngGet",
                                                                    pc        |->  Head(stack[self]).pc,
                                                                    processed |->  processed[self],
                                                                    exhausted |->  exhausted[self],
                                                                    stop      |->  stop[self],
                                                                    uns       |->  uns[self],
                                                                    gd        |->  gd[self],
                                                                    gnb       |->  gnb[self],
                                                                    glen      |->  glen[self] ] >>
                                                                \o Tail(stack[self])]
                        /\ processed' = [processed EXCEPT ![self] = 0]
                        /\ exhausted' = [exhausted EXCEPT ![self] = FALSE]
                        /\ stop' = [stop EXCEPT ![self] = FALSE]
                        /\ uns' = [uns EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "dg0"]
                        /\ UNCHANGED << spr, snb, slen >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ pick' = [pick EXCEPT ![self] = Head(stack[self]).pick]
                        /\ spr' = [spr EXCEPT ![self] = Head(stack[self]).spr]
                        /\ snb' = [snb EXCEPT ![self] = Head(stack[self]).snb]
                        /\ slen' = [slen EXCEPT ![self] = Head(stack[self]).slen]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << gd, gnb, glen, processed, exhausted, 
                                        stop, uns >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, snb2, od, 
                             kind, n, done, ai >>

getSleep(self) == gs0(self) \/ gs1(self) \/ gs2(self)

sn0(self) == /\ pc[self] = "sn0"
             /\ IF snb2[self]
                   THEN /\ IF ~allSeeded
                              THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWorkTry",
                                                                            pc        |->  "sn1" ] >>
                                                                        \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "swt"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "sn1"]
                                   /\ stack' = stack
                   ELSE /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "forceFS",
                                                                 pc        |->  "sn1" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ff"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, snb2, od, kind, n, done, ai >>

sn1(self) == /\ pc[self] = "sn1"
             /\ IF snb2[self]
                   THEN /\ rv' = [rv EXCEPT ![self] = IF operational THEN 0 ELSE -2]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ snb2' = [snb2 EXCEPT ![self] = Head(stack[self]).snb2]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ operational
                        /\ rv' = [rv EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ snb2' = [snb2 EXCEPT ![self] = Head(stack[self]).snb2]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, od, 
                             kind, n, done, ai >>

sleepNonop(self) == sn0(self) \/ sn1(self)

ro0(self) == /\ pc[self] = "ro0"
             /\ seedLock[od[self]] = NoProc
             /\ seedLock' = [seedLock EXCEPT ![od[self]] = self]
             /\ IF MustReseed(od[self])
                   THEN /\ /\ rsd' = [rsd EXCEPT ![self] = od[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reseedLocked",
                                                                    pc        |->  "ro1",
                                                                    rep       |->  rep[self],
                                                                    reg       |->  reg[self],
                                                                    rsd       |->  rsd[self] ] >>
                                                                \o stack[self]]
                        /\ rep' = [rep EXCEPT ![self] = 0]
                        /\ reg' = [reg EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "rs0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ro1"]
                        /\ UNCHANGED << stack, rsd, rep, reg >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, swForce, swWait, 
                             i, sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

ro1(self) == /\ pc[self] = "ro1"
             /\ seedLock' = [seedLock EXCEPT ![od[self]] = NoProc]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ od' = [od EXCEPT ![self] = Head(stack[self]).od]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, snb2, kind, n, done, ai >>

reseedOne(self) == ro0(self) \/ ro1(self)

rq0(self) == /\ pc[self] = "rq0"
             /\ \E k \in ReqKinds \cup {"stop"}:
                  \E s \in IF k = "stop" THEN {0}
                           ELSE IF k \in {"pr", "prnb"} THEN PRSizes ELSE ReqSizes:
                    /\ kind' = [kind EXCEPT ![self] = k]
                    /\ n' = [n EXCEPT ![self] = s]
             /\ IF kind'[self] = "stop"
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, spr, snb, slen, pick, snb2 >>
                   ELSE /\ IF kind'[self] = "full"
                              THEN /\ pc' = [pc EXCEPT ![self] = "rqF"]
                                   /\ UNCHANGED << stack, spr, snb, slen, pick, 
                                                   snb2 >>
                              ELSE /\ IF kind'[self] = "fnb"
                                         THEN /\ /\ snb2' = [snb2 EXCEPT ![self] = TRUE]
                                                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "sleepNonop",
                                                                                          pc        |->  "rqG1",
                                                                                          snb2      |->  snb2[self] ] >>
                                                                                      \o stack[self]]
                                              /\ pc' = [pc EXCEPT ![self] = "sn0"]
                                              /\ UNCHANGED << spr, snb, slen, 
                                                              pick >>
                                         ELSE /\ IF kind'[self] = "nb"
                                                    THEN /\ /\ slen' = [slen EXCEPT ![self] = n'[self]]
                                                            /\ snb' = [snb EXCEPT ![self] = TRUE]
                                                            /\ spr' = [spr EXCEPT ![self] = FALSE]
                                                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getSleep",
                                                                                                     pc        |->  "rqE",
                                                                                                     pick      |->  pick[self],
                                                                                                     spr       |->  spr[self],
                                                                                                     snb       |->  snb[self],
                                                                                                     slen      |->  slen[self] ] >>
                                                                                                 \o stack[self]]
                                                         /\ pick' = [pick EXCEPT ![self] = 0]
                                                         /\ pc' = [pc EXCEPT ![self] = "gs0"]
                                                         /\ snb2' = snb2
                                                    ELSE /\ IF kind'[self] = "pr"
                                                               THEN /\ /\ snb2' = [snb2 EXCEPT ![self] = FALSE]
                                                                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "sleepNonop",
                                                                                                                pc        |->  "rqP1",
                                                                                                                snb2      |->  snb2[self] ] >>
                                                                                                            \o stack[self]]
                                                                    /\ pc' = [pc EXCEPT ![self] = "sn0"]
                                                               ELSE /\ /\ snb2' = [snb2 EXCEPT ![self] = TRUE]
                                                                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "sleepNonop",
                                                                                                                pc        |->  "rqQ1",
                                                                                                                snb2      |->  snb2[self] ] >>
                                                                                                            \o stack[self]]
                                                                    /\ pc' = [pc EXCEPT ![self] = "sn0"]
                                                         /\ UNCHANGED << spr, 
                                                                         snb, 
                                                                         slen, 
                                                                         pick >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, od, done, 
                             ai >>

rqE(self) == /\ pc[self] = "rqE"
             /\ rv' = [rv EXCEPT ![self] = 0]
             /\ kind' = [kind EXCEPT ![self] = "full"]
             /\ n' = [n EXCEPT ![self] = 0]
             /\ done' = [done EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "rq0"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, injRet, freshOut, 
                             freshES, goodSeed, outSince, tried, viol, stack, 
                             ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                             collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                             swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, ai >>

rqF(self) == /\ pc[self] = "rqF"
             /\ IF done[self] < n[self]
                   THEN /\ /\ snb2' = [snb2 EXCEPT ![self] = FALSE]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "sleepNonop",
                                                                    pc        |->  "rqF1",
                                                                    snb2      |->  snb2[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "sn0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rqE"]
                        /\ UNCHANGED << stack, snb2 >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, od, kind, n, done, ai >>

rqF1(self) == /\ pc[self] = "rqF1"
              /\ /\ slen' = [slen EXCEPT ![self] = n[self] - done[self]]
                 /\ snb' = [snb EXCEPT ![self] = FALSE]
                 /\ spr' = [spr EXCEPT ![self] = FALSE]
                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getSleep",
                                                          pc        |->  "rqF2",
                                                          pick      |->  pick[self],
                                                          spr       |->  spr[self],
                                                          snb       |->  snb[self],
                                                          slen      |->  slen[self] ] >>
                                                      \o stack[self]]
              /\ pick' = [pick EXCEPT ![self] = 0]
              /\ pc' = [pc EXCEPT ![self] = "gs0"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, prLock, resets, forces, dues, 
                              resetGen, esGen, swRet, good, rv, injRet, 
                              freshOut, freshES, goodSeed, outSince, tried, 
                              viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                              coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                              swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                              glen, processed, exhausted, stop, uns, snb2, od, 
                              kind, n, done, ai >>

rqF2(self) == /\ pc[self] = "rqF2"
              /\ IF rv[self] < 0 /\ FullRetry
                    THEN /\ pc' = [pc EXCEPT ![self] = "rqF"]
                         /\ UNCHANGED << viol, done >>
                    ELSE /\ IF rv[self] < 0
                               THEN /\ viol' = (viol \cup {"FullShort"})
                                    /\ pc' = [pc EXCEPT ![self] = "rqE"]
                                    /\ done' = done
                               ELSE /\ done' = [done EXCEPT ![self] = done[self] + rv[self]]
                                    /\ pc' = [pc EXCEPT ![self] = "rqF"]
                                    /\ viol' = viol
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, prLock, resets, forces, dues, 
                              resetGen, esGen, swRet, good, rv, injRet, 
                              freshOut, freshES, goodSeed, outSince, tried, 
                              stack, ud, sd, lockMode, dfi, forced, thr, ep, 
                              eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                              reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                              gnb, glen, processed, exhausted, stop, uns, spr, 
                              snb, slen, pick, snb2, od, kind, n, ai >>

rqG1(self) == /\ pc[self] = "rqG1"
              /\ IF rv[self] < 0
                    THEN /\ pc' = [pc EXCEPT ![self] = "rqE"]
                         /\ UNCHANGED << stack, spr, snb, slen, pick >>
                    ELSE /\ /\ slen' = [slen EXCEPT ![self] = n[self]]
                            /\ snb' = [snb EXCEPT ![self] = TRUE]
                            /\ spr' = [spr EXCEPT ![self] = FALSE]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getSleep",
                                                                     pc        |->  "rqE",
                                                                     pick      |->  pick[self],
                                                                     spr       |->  spr[self],
                                                                     snb       |->  snb[self],
                                                                     slen      |->  slen[self] ] >>
                                                                 \o stack[self]]
                         /\ pick' = [pick EXCEPT ![self] = 0]
                         /\ pc' = [pc EXCEPT ![self] = "gs0"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, prLock, resets, forces, dues, 
                              resetGen, esGen, swRet, good, rv, injRet, 
                              freshOut, freshES, goodSeed, outSince, tried, 
                              viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                              coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                              swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                              glen, processed, exhausted, stop, uns, snb2, od, 
                              kind, n, done, ai >>

rqP1(self) == /\ pc[self] = "rqP1"
              /\ IF prLock # NoProc
                    THEN /\ pc' = [pc EXCEPT ![self] = "rqE"]
                         /\ UNCHANGED << prLock, stack, spr, snb, slen, pick >>
                    ELSE /\ prLock' = self
                         /\ /\ slen' = [slen EXCEPT ![self] = n[self]]
                            /\ snb' = [snb EXCEPT ![self] = FALSE]
                            /\ spr' = [spr EXCEPT ![self] = TRUE]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getSleep",
                                                                     pc        |->  "rqP2",
                                                                     pick      |->  pick[self],
                                                                     spr       |->  spr[self],
                                                                     snb       |->  snb[self],
                                                                     slen      |->  slen[self] ] >>
                                                                 \o stack[self]]
                         /\ pick' = [pick EXCEPT ![self] = 0]
                         /\ pc' = [pc EXCEPT ![self] = "gs0"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, resets, forces, dues, resetGen, 
                              esGen, swRet, good, rv, injRet, freshOut, 
                              freshES, goodSeed, outSince, tried, viol, ud, sd, 
                              lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                              injd, seeded, sdd, rsd, rep, reg, swForce, 
                              swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                              processed, exhausted, stop, uns, snb2, od, kind, 
                              n, done, ai >>

rqP2(self) == /\ pc[self] = "rqP2"
              /\ prLock' = NoProc
              /\ pc' = [pc EXCEPT ![self] = "rqE"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, resets, forces, dues, resetGen, 
                              esGen, swRet, good, rv, injRet, freshOut, 
                              freshES, goodSeed, outSince, tried, viol, stack, 
                              ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                              collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                              swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                              processed, exhausted, stop, uns, spr, snb, slen, 
                              pick, snb2, od, kind, n, done, ai >>

rqQ1(self) == /\ pc[self] = "rqQ1"
              /\ IF rv[self] < 0 \/ prLock # NoProc
                    THEN /\ pc' = [pc EXCEPT ![self] = "rqE"]
                         /\ UNCHANGED << prLock, stack, spr, snb, slen, pick >>
                    ELSE /\ prLock' = self
                         /\ /\ slen' = [slen EXCEPT ![self] = n[self]]
                            /\ snb' = [snb EXCEPT ![self] = TRUE]
                            /\ spr' = [spr EXCEPT ![self] = TRUE]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getSleep",
                                                                     pc        |->  "rqQ2",
                                                                     pick      |->  pick[self],
                                                                     spr       |->  spr[self],
                                                                     snb       |->  snb[self],
                                                                     slen      |->  slen[self] ] >>
                                                                 \o stack[self]]
                         /\ pick' = [pick EXCEPT ![self] = 0]
                         /\ pc' = [pc EXCEPT ![self] = "gs0"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, resets, forces, dues, resetGen, 
                              esGen, swRet, good, rv, injRet, freshOut, 
                              freshES, goodSeed, outSince, tried, viol, ud, sd, 
                              lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                              injd, seeded, sdd, rsd, rep, reg, swForce, 
                              swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                              processed, exhausted, stop, uns, snb2, od, kind, 
                              n, done, ai >>

rqQ2(self) == /\ pc[self] = "rqQ2"
              /\ prLock' = NoProc
              /\ pc' = [pc EXCEPT ![self] = "rqE"]
              /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                              operational, allSeeded, reseedRunning, running, 
                              bringups, task, resets, forces, dues, resetGen, 
                              esGen, swRet, good, rv, injRet, freshOut, 
                              freshES, goodSeed, outSince, tried, viol, stack, 
                              ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                              collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                              swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                              processed, exhausted, stop, uns, spr, snb, slen, 
                              pick, snb2, od, kind, n, done, ai >>

r(self) == rq0(self) \/ rqE(self) \/ rqF(self) \/ rqF1(self) \/ rqF2(self)
              \/ rqG1(self) \/ rqP1(self) \/ rqP2(self) \/ rqQ1(self)
              \/ rqQ2(self)

wk(self) == /\ pc[self] = "wk"
            /\ \/ Len(Starts) + NewBringups > 0
               \/ (\A d \in Nodes : fs[d]) /\ ~allSeeded
            /\ LET free == FreeTasks IN
                 LET starts == Starts IN
                   LET nb == NewBringups IN
                     /\ task' = [x \in TaskProcs |->
                                 IF \E j \in 1..Len(starts) : free[j] = x
                                 THEN starts[CHOOSE j \in 1..Len(starts) : free[j] = x]
                                 ELSE IF \E j \in Len(starts)+1..Len(starts)+nb : free[j] = x
                                 THEN Bringup ELSE task[x]]
                     /\ reseedRunning' = [d \in Drngs |->
                                          reseedRunning[d] \/ \E j \in 1..Len(starts) :
                                                                starts[j] = d]
                     /\ running' = running + Len(starts) + nb
                     /\ bringups' = bringups + nb
            /\ IF (\A d \in Nodes : fs[d]) /\ ~allSeeded
                  THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "noteAll",
                                                                pc        |->  "wk" ] >>
                                                            \o stack[self]]
                       /\ pc' = [pc EXCEPT ![self] = "na1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "wk"]
                       /\ stack' = stack
            /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                            operational, allSeeded, prLock, resets, forces, 
                            dues, resetGen, esGen, swRet, good, rv, injRet, 
                            freshOut, freshES, goodSeed, outSince, tried, viol, 
                            ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                            collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                            swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                            processed, exhausted, stop, uns, spr, snb, slen, 
                            pick, snb2, od, kind, n, done, ai >>

w(self) == wk(self)

tk0(self) == /\ pc[self] = "tk0"
             /\ task[self] # NoTask
             /\ IF task[self] = Bringup
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWork",
                                                                    pc        |->  "tk1",
                                                                    i         |->  i[self],
                                                                    sel       |->  sel[self],
                                                                    busy      |->  busy[self],
                                                                    swForce   |->  swForce[self],
                                                                    swWait    |->  swWait[self] ] >>
                                                                \o stack[self]]
                           /\ swForce' = [swForce EXCEPT ![self] = TRUE]
                           /\ swWait' = [swWait EXCEPT ![self] = FALSE]
                        /\ i' = [i EXCEPT ![self] = 0]
                        /\ sel' = [sel EXCEPT ![self] = NoTask]
                        /\ busy' = [busy EXCEPT ![self] = NoTask]
                        /\ pc' = [pc EXCEPT ![self] = "sw1"]
                        /\ od' = od
                   ELSE /\ /\ od' = [od EXCEPT ![self] = task[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reseedOne",
                                                                    pc        |->  "tk1",
                                                                    od        |->  od[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ro0"]
                        /\ UNCHANGED << swForce, swWait, i, sel, busy >>
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, rd, 
                             rnb, gd, gnb, glen, processed, exhausted, stop, 
                             uns, spr, snb, slen, pick, snb2, kind, n, done, 
                             ai >>

tk1(self) == /\ pc[self] = "tk1"
             /\ IF task[self] = Bringup
                   THEN /\ bringups' = bringups - 1
                        /\ UNCHANGED reseedRunning
                   ELSE /\ reseedRunning' = [reseedRunning EXCEPT ![task[self]] = FALSE]
                        /\ UNCHANGED bringups
             /\ running' = running - 1
             /\ task' = [task EXCEPT ![self] = NoTask]
             /\ pc' = [pc EXCEPT ![self] = "tk0"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, prLock, resets, forces, 
                             dues, resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done, ai >>

t(self) == tk0(self) \/ tk1(self)

mo0(self) == /\ pc[self] = "mo0"
             /\ ~allSeeded
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seedWorkTry",
                                                      pc        |->  "mo0" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "swt"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                             coll, collV, injd, seeded, sdd, rsd, rep, reg, 
                             swForce, swWait, i, sel, busy, rd, rnb, gd, gnb, 
                             glen, processed, exhausted, stop, uns, spr, snb, 
                             slen, pick, snb2, od, kind, n, done, ai >>

m(self) == mo0(self)

ad0(self) == /\ pc[self] = "ad0"
             /\ IF resets < MaxResets \/ forces < MaxForces
                   THEN /\ \/ /\ resets < MaxResets
                              /\ resets' = resets + 1
                              /\ IF ResetEsFirst
                                    THEN /\ esGen' = esGen + 1
                                    ELSE /\ TRUE
                                         /\ esGen' = esGen
                              /\ pc' = [pc EXCEPT ![self] = "ad1"]
                              /\ UNCHANGED <<force, forces>>
                           \/ /\ forces < MaxForces
                              /\ forces' = forces + 1
                              /\ IF Disable(0)
                                    THEN /\ force' = [force EXCEPT ![0] = fs[0]]
                                         /\ pc' = [pc EXCEPT ![self] = "ad0"]
                                    ELSE /\ pc' = [pc EXCEPT ![self] = "ad4"]
                                         /\ force' = force
                              /\ UNCHANGED <<resets, esGen>>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << force, resets, forces, esGen >>
             /\ UNCHANGED << fs, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, dues, resetGen, swRet, 
                             good, rv, injRet, freshOut, freshES, goodSeed, 
                             outSince, tried, viol, stack, ud, sd, lockMode, 
                             dfi, forced, thr, ep, eg, coll, collV, injd, 
                             seeded, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

ad1(self) == /\ pc[self] = "ad1"
             /\ IF ai[self] < NN
                   THEN /\ lock[ai[self]] = NoProc
                        /\ used' = [used EXCEPT ![ai[self]] = 0]
                        /\ fs' = [fs EXCEPT ![ai[self]] = FALSE]
                        /\ goodSeed' = [goodSeed EXCEPT ![ai[self]] = FALSE]
                        /\ force' = [force EXCEPT ![ai[self]] = FALSE]
                        /\ initiated' = [initiated EXCEPT ![ai[self]] = FALSE]
                        /\ due' = [due EXCEPT ![ai[self]] = TRUE]
                        /\ resetGen' = [resetGen EXCEPT ![ai[self]] = resetGen[ai[self]] + 1]
                        /\ freshOut' = [freshOut EXCEPT ![ai[self]] = 0]
                        /\ freshES' = [freshES EXCEPT ![ai[self]] = ZeroV]
                        /\ IF ai[self] = 0
                              THEN /\ allSeeded' = FALSE
                                   /\ operational' = FALSE
                              ELSE /\ TRUE
                                   /\ UNCHANGED << operational, allSeeded >>
                        /\ ai' = [ai EXCEPT ![self] = ai[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "ad1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ad2"]
                        /\ UNCHANGED << fs, force, initiated, used, due, 
                                        operational, allSeeded, resetGen, 
                                        freshOut, freshES, goodSeed, ai >>
             /\ UNCHANGED << lock, seedLock, reseedRunning, running, bringups, 
                             task, prLock, resets, forces, dues, esGen, swRet, 
                             good, rv, injRet, outSince, tried, viol, stack, 
                             ud, sd, lockMode, dfi, forced, thr, ep, eg, coll, 
                             collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                             swWait, i, sel, busy, rd, rnb, gd, gnb, glen, 
                             processed, exhausted, stop, uns, spr, snb, slen, 
                             pick, snb2, od, kind, n, done >>

ad2(self) == /\ pc[self] = "ad2"
             /\ lock[PR] = NoProc
             /\ used' = [used EXCEPT ![PR] = 0]
             /\ fs' = [fs EXCEPT ![PR] = FALSE]
             /\ goodSeed' = [goodSeed EXCEPT ![PR] = FALSE]
             /\ force' = [force EXCEPT ![PR] = FALSE]
             /\ initiated' = [initiated EXCEPT ![PR] = FALSE]
             /\ due' = [due EXCEPT ![PR] = TRUE]
             /\ resetGen' = [resetGen EXCEPT ![PR] = resetGen[PR] + 1]
             /\ freshOut' = [freshOut EXCEPT ![PR] = 0]
             /\ freshES' = [freshES EXCEPT ![PR] = ZeroV]
             /\ pc' = [pc EXCEPT ![self] = "ad3"]
             /\ UNCHANGED << lock, seedLock, operational, allSeeded, 
                             reseedRunning, running, bringups, task, prLock, 
                             resets, forces, dues, esGen, swRet, good, rv, 
                             injRet, outSince, tried, viol, stack, ud, sd, 
                             lockMode, dfi, forced, thr, ep, eg, coll, collV, 
                             injd, seeded, sdd, rsd, rep, reg, swForce, swWait, 
                             i, sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done, ai >>

ad3(self) == /\ pc[self] = "ad3"
             /\ allSeeded' = FALSE
             /\ ai' = [ai EXCEPT ![self] = 0]
             /\ IF ~ResetEsFirst
                   THEN /\ esGen' = esGen + 1
                   ELSE /\ TRUE
                        /\ esGen' = esGen
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "forceAll",
                                                      pc        |->  "ad0" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "fa0"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, reseedRunning, running, bringups, 
                             task, prLock, resets, forces, dues, resetGen, 
                             swRet, good, rv, injRet, freshOut, freshES, 
                             goodSeed, outSince, tried, viol, ud, sd, lockMode, 
                             dfi, forced, thr, ep, eg, coll, collV, injd, 
                             seeded, sdd, rsd, rep, reg, swForce, swWait, i, 
                             sel, busy, rd, rnb, gd, gnb, glen, processed, 
                             exhausted, stop, uns, spr, snb, slen, pick, snb2, 
                             od, kind, n, done >>

ad4(self) == /\ pc[self] = "ad4"
             /\ IF ai[self] < NN
                   THEN /\ force' = [force EXCEPT ![ai[self]] = fs[ai[self]]]
                        /\ ai' = [ai EXCEPT ![self] = ai[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "ad4"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ad5"]
                        /\ UNCHANGED << force, ai >>
             /\ UNCHANGED << fs, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done >>

ad5(self) == /\ pc[self] = "ad5"
             /\ ai' = [ai EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "ad0"]
             /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                             operational, allSeeded, reseedRunning, running, 
                             bringups, task, prLock, resets, forces, dues, 
                             resetGen, esGen, swRet, good, rv, injRet, 
                             freshOut, freshES, goodSeed, outSince, tried, 
                             viol, stack, ud, sd, lockMode, dfi, forced, thr, 
                             ep, eg, coll, collV, injd, seeded, sdd, rsd, rep, 
                             reg, swForce, swWait, i, sel, busy, rd, rnb, gd, 
                             gnb, glen, processed, exhausted, stop, uns, spr, 
                             snb, slen, pick, snb2, od, kind, n, done >>

a(self) == ad0(self) \/ ad1(self) \/ ad2(self) \/ ad3(self) \/ ad4(self)
              \/ ad5(self)

en0 == /\ pc["env"] = "en0"
       /\ \/ /\ AnyDue \/ dues < MaxDue
             /\ \E d \in Nodes:
                  due' = [due EXCEPT ![d] = TRUE]
             /\ IF ~AnyDue
                   THEN /\ dues' = dues + 1
                   ELSE /\ TRUE
                        /\ dues' = dues
             /\ pc' = [pc EXCEPT !["env"] = "en0"]
             /\ good' = good
          \/ /\ Liveness /\ ~good
             /\ good' = TRUE
             /\ pc' = [pc EXCEPT !["env"] = "en0"]
             /\ UNCHANGED <<due, dues>>
          \/ /\ AnyDue
             /\ pc' = [pc EXCEPT !["env"] = "enQ"]
             /\ UNCHANGED <<due, dues, good>>
          \/ /\ ~AnyDue /\ Quiet
             /\ pc' = [pc EXCEPT !["env"] = "en0"]
             /\ UNCHANGED <<due, dues, good>>
       /\ UNCHANGED << fs, force, initiated, used, lock, seedLock, operational, 
                       allSeeded, reseedRunning, running, bringups, task, 
                       prLock, resets, forces, resetGen, esGen, swRet, rv, 
                       injRet, freshOut, freshES, goodSeed, outSince, tried, 
                       viol, stack, ud, sd, lockMode, dfi, forced, thr, ep, eg, 
                       coll, collV, injd, seeded, sdd, rsd, rep, reg, swForce, 
                       swWait, i, sel, busy, rd, rnb, gd, gnb, glen, processed, 
                       exhausted, stop, uns, spr, snb, slen, pick, snb2, od, 
                       kind, n, done, ai >>

enQ == /\ pc["env"] = "enQ"
       /\ \/ /\ Quiet
             /\ good' = good
          \/ /\ Liveness /\ ~good
             /\ good' = TRUE
       /\ pc' = [pc EXCEPT !["env"] = "enQ"]
       /\ UNCHANGED << fs, force, initiated, used, due, lock, seedLock, 
                       operational, allSeeded, reseedRunning, running, 
                       bringups, task, prLock, resets, forces, dues, resetGen, 
                       esGen, swRet, rv, injRet, freshOut, freshES, goodSeed, 
                       outSince, tried, viol, stack, ud, sd, lockMode, dfi, 
                       forced, thr, ep, eg, coll, collV, injd, seeded, sdd, 
                       rsd, rep, reg, swForce, swWait, i, sel, busy, rd, rnb, 
                       gd, gnb, glen, processed, exhausted, stop, uns, spr, 
                       snb, slen, pick, snb2, od, kind, n, done, ai >>

e == en0 \/ enQ

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == e
           \/ (\E self \in ProcSet:  \/ unset(self) \/ noteAll(self)
                                     \/ seedEs(self) \/ seed(self)
                                     \/ reseedLocked(self) \/ seedWork(self)
                                     \/ seedWorkTry(self) \/ forceFS(self)
                                     \/ forceAll(self) \/ getReseed(self)
                                     \/ drngGet(self) \/ getSleep(self)
                                     \/ sleepNonop(self) \/ reseedOne(self))
           \/ (\E self \in Req: r(self))
           \/ (\E self \in WorkerProcs: w(self))
           \/ (\E self \in TaskProcs: t(self))
           \/ (\E self \in MonProcs: m(self))
           \/ (\E self \in AdminProcs: a(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Req : /\ SF_vars(r(self))
                             /\ SF_vars(sleepNonop(self))
                             /\ SF_vars(getSleep(self))
                             /\ SF_vars(noteAll(self))
                             /\ SF_vars(seedEs(self))
                             /\ SF_vars(seed(self))
                             /\ SF_vars(seedWork(self))
                             /\ SF_vars(seedWorkTry(self))
                             /\ SF_vars(forceFS(self))
                             /\ SF_vars(unset(self))
                             /\ SF_vars(reseedLocked(self))
                             /\ SF_vars(getReseed(self))
                             /\ SF_vars(drngGet(self))
        /\ \A self \in WorkerProcs : SF_vars(w(self)) /\ SF_vars(noteAll(self))
        /\ \A self \in TaskProcs : /\ SF_vars(t(self))
                                   /\ SF_vars(seedWork(self))
                                   /\ SF_vars(reseedOne(self))
                                   /\ SF_vars(noteAll(self))
                                   /\ SF_vars(seedEs(self))
                                   /\ SF_vars(seed(self))
                                   /\ SF_vars(reseedLocked(self))
        /\ \A self \in MonProcs : /\ SF_vars(m(self))
                                  /\ SF_vars(seedWorkTry(self))
                                  /\ SF_vars(noteAll(self))
                                  /\ SF_vars(seedEs(self))
                                  /\ SF_vars(seed(self))
                                  /\ SF_vars(seedWork(self))
        /\ \A self \in AdminProcs : /\ SF_vars(a(self))
                                    /\ SF_vars(forceAll(self))
                                    /\ SF_vars(noteAll(self))
                                    /\ SF_vars(seedEs(self))
                                    /\ SF_vars(seed(self))
                                    /\ SF_vars(seedWork(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

\* The specification of the liveness checks: one fairness condition per
\* process, over its own actions and those of the procedures it calls. A
\* process has one program counter, so at most one of them is enabled at a
\* time. TLC expands the fairness conditions of a liveness check into
\* disjunctive normal form, which the conditions per procedure of Spec make
\* too large to compute.
\*
\* Weak fairness, which the strong fairness of Spec implies: it suffices in
\* every configuration that checks liveness. They have one requester each;
\* requesters that take a lock from each other again and again would need
\* strong fairness, a fair lock. No fairness for the environment: the
\* properties assume what they need of it.
ReqStep(self) ==
    \/ r(self) \/ sleepNonop(self) \/ getSleep(self) \/ noteAll(self)
    \/ seedEs(self) \/ seed(self) \/ seedWork(self) \/ seedWorkTry(self)
    \/ forceFS(self) \/ unset(self) \/ reseedLocked(self) \/ getReseed(self)
    \/ drngGet(self)
TaskStep(self) ==
    \/ t(self) \/ seedWork(self) \/ reseedOne(self) \/ noteAll(self)
    \/ seedEs(self) \/ seed(self) \/ reseedLocked(self)
MonStep(self) ==
    \/ m(self) \/ seedWorkTry(self) \/ noteAll(self) \/ seedEs(self)
    \/ seed(self) \/ seedWork(self)
AdminStep(self) ==
    \/ a(self) \/ forceAll(self) \/ seedWork(self) \/ noteAll(self)
    \/ seedEs(self) \/ seed(self)

LiveSpec == /\ Init /\ [][Next]_vars
            /\ \A self \in Req : WF_vars(ReqStep(self))
            /\ \A self \in WorkerProcs : WF_vars(w(self) \/ noteAll(self))
            /\ \A self \in TaskProcs : WF_vars(TaskStep(self))
            /\ \A self \in MonProcs : WF_vars(MonStep(self))
            /\ \A self \in AdminProcs : WF_vars(AdminStep(self))

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ fs \in [Drngs -> BOOLEAN]
    /\ force \in [Drngs -> BOOLEAN]
    /\ used \in [Drngs -> 0..UCap]
    /\ lock \in [Drngs -> AllProcs \cup {NoProc}]
    /\ seedLock \in [Drngs -> AllProcs \cup {NoProc}]
    /\ running \in 0..Cardinality(TaskProcs)
    /\ bringups \in 0..Cardinality(TaskProcs)
    /\ outSince \in [Drngs -> 0..UCap]
    /\ resetGen \in [Drngs -> 0..MaxResets]
    /\ esGen \in 0..MaxResets
    /\ dues \in 0..(IF AnyDue THEN 0 ELSE MaxDue)

\* No thread returns from a call, idles or ends with a lock held.
IdleLabels == {"rq0", "rqE", "Done", "wk", "tk0", "mo0", "ad0", "en0", "enQ"}
LocksReleased ==
    \A p \in ProcSet :
        pc[p] \in IdleLabels =>
            /\ \A d \in Drngs : lock[d] # p /\ seedLock[d] # p
            /\ prLock # p

\* The counters of the reseed worker match its tasks.
TaskAccounting ==
    /\ running = Cardinality({x \in TaskProcs : task[x] # NoTask})
    /\ bringups = Cardinality({x \in TaskProcs : task[x] = Bringup})
    /\ \A d \in Drngs : reseedRunning[d] <=> \E x \in TaskProcs : task[x] = d

\* At rest nothing is locked and, with a reseed worker, every DRNG that
\* serves requests is fully seeded, none is spent or - unless every request
\* reseeds - due for a reseed, and the ESDM is operational.
AtRest ==
    /\ Quiet
    /\ Worker => /\ Len(Starts) + NewBringups = 0
                 /\ (\A d \in Nodes : fs[d]) => allSeeded
    /\ Monitor => allSeeded
QuietSeeded ==
    AtRest =>
        /\ \A d \in Drngs : lock[d] = NoProc /\ seedLock[d] = NoProc
        /\ prLock = NoProc
        /\ Worker => /\ \A d \in Nodes : /\ fs[d]
                                          /\ Budget(d, used[d]) > 0
                                          /\ (PerRequest \/ ~MustReseed(d))
                     /\ allSeeded /\ operational

\* The ESDM is operational only while the initial DRNG, every request's
\* fallback, is fully seeded.
OperationalSound == lock[0] = NoProc => (operational => fs[0])

\* ... and the initial DRNG being fully seeded makes it operational, but for
\* the window of a seeding locked per injection (se2).
OperationalComplete ==
    (lock[0] = NoProc /\ fs[0]) =>
        (operational \/ \E p \in ProcSet : pc[p] = "se2")

\* all_online_nodes_seeded is wrong only inside the windows the code
\* closes: esdm_unset_fully_seeded(), esdm_drngs_note_all_seeded() and
\* esdm_reset().
AllSeededSound ==
    (allSeeded /\ \E d \in Nodes : ~fs[d]) =>
        \E p \in ProcSet : pc[p] \in {"us2", "na2", "ad1", "ad2", "ad3"}

\* The output of a DRNG since its last seed that met the seeding rule, and
\* the count the code keeps of it: no node DRNG starts a chunk past the
\* maximum, the initial DRNG stops at its budget.
OutputBound ==
    Budgeted =>
        /\ \A d \in 1..NN-1 : /\ outSince[d] < MaxBits + SetMax(ReqSizes)
                              /\ used[d] < MaxBits + SetMax(ReqSizes)
        /\ outSince[0] <= Min(MaxBits, ThreshBits)
        /\ used[0] <= Min(MaxBits, ThreshBits)

\* Every DRNG declared fully seeded has the entropy it needs, injected since
\* its last output: no state compromise extends across a seeding that is
\* added up from several collections (catastrophic reseeding). The security
\* strength for a reseed, the initial seed size for a DRNG not fully seeded
\* - with NTG.1 the latter is Ntg1Seed.
CreditSinceOutput == "CreditSinceOutput" \notin viol

\* A PR chunk is no larger than the entropy injected for it less the
\* oversampling.
PROutput == "PROutput" \notin viol

\* Every chunk of the initial or a node DRNG comes from a seed that met the
\* seeding rule with entropy injected after the DRNG's previous output: an
\* ESDM that is not fully seeded - its sources failing or short - outputs
\* nothing.
OutputFromSeeded == "OutputUnseeded" \notin viol

\* With the NTG.1 seeding strategy, a DRNG not fully seeded becomes fully
\* seeded only with NtgMin from two sources, or from an NTG.1 Jitter RNG,
\* since its last output.
Ntg1Seed == "Ntg1Seed" \notin viol

\* The PR DRNG serves only after its initial full seed.
PRInitiated == "PRInitiated" \notin viol

ChunkBound == viol \cap {"ChunkPastMax", "InitPastBudget"} = {}

\* A blocking request returns all it was asked for.
FullComplete == "FullShort" \notin viol

\* With a reseed interval of zero seconds, a blocking request seeds the
\* initial or node DRNG before every chunk it takes from it.
ReseedPerRequest == "NoReseed" \notin viol

-----------------------------------------------------------------------------
(* Liveness, under the assumption that the sources eventually deliver for *)
(* good and that eventually no further reseed falls due by time, as with *)
(* MaxDue, or with AnyDue once time stopped.                            *)
(*                                                                       *)
(* The worker starts the reseeds due before the bring-ups, the one of    *)
(* the initial DRNG last. With fewer task threads than DRNGs, reseeds    *)
(* that fall due again and again keep the others waiting: by time,       *)
(* without the assumption above, the initial DRNG is not brought up      *)
(* (BringupNotStarved does not hold); by requests that use up a DRNG     *)
(* again and again, another is not brought up (SeededUnderLoad does not  *)
(* hold) or the initial DRNG, which no request needs then, stays spent.  *)
(* Every DRNG gets its turn with a task thread per DRNG, or once the     *)
(* requests stop: RequestsStop.                                          *)

Settled == <>[]good /\ (AnyDue => <>[](pc["env"] = "enQ"))

EventuallyOperational == Settled => <>[]operational

SeededUnderLoad == Settled => []<>allSeeded

RequestsStop ==
    (Worker /\ Cardinality(TaskProcs) < NN)
        => <>[](\A p \in Req : pc[p] = "Done")

AllEventuallySeeded == (Settled /\ RequestsStop) => []<>allSeeded

RequestsReturn ==
    Settled =>
        \A p \in Req : [](pc[p] \notin {"rq0", "Done"} => <>(pc[p] = "rq0"))

SpentReseeded ==
    (Settled /\ RequestsStop) =>
        \A d \in Nodes :
            [](fs[d] /\ Budget(d, used[d]) = 0
               => <>(~fs[d] \/ Budget(d, used[d]) > 0))

BringupNotStarved == <>[]good => <>[]operational
=============================================================================
