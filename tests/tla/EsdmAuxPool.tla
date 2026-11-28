----------------------------- MODULE EsdmAuxPool -----------------------------
(***************************************************************************)
(* The auxiliary entropy pool, esdm/esdm_es_aux.c, at the granularity of   *)
(* its locks and atomics: the pools with their lock and entropy count, the *)
(* writers esdm_pool_insert_aux(), esdm_pool_add_entropy(),                *)
(* esdm_pool_set_entropy(0), esdm_aux_init() and                           *)
(* esdm_set_write_wakeup_bits(), the seedings of the DRNGs that collect    *)
(* from it at once through esdm_aux_get_backtrack(), and the readers of    *)
(* the need for entropy, esdm_need_entropy(), on their own and as          *)
(* esdm_shm_status_set_need_entropy() publishes it after an operation.     *)
(* One step is one atomic variable access or one critical section; the     *)
(* labels name the C functions they come from.                             *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - Entropy is counted in units: the digest size of a pool is Cap, the    *)
(*   SP800-90C oversampling OsrU, and a build with                         *)
(*   ESDM_AUX_INPUT_HAS_FULL_ENTROPY has OsrU = 0.                         *)
(* - The XDRBG of a pool is its seed_initialized flag. An insert or        *)
(*   extraction of the XOF may fail where XofFail says so, which discards  *)
(*   the state. The data itself is left out: an insert carries at least    *)
(*   as many bits as it is credited with.                                  *)
(* - The pools start initialized for the seed: esdm_es_mgr_initialize()    *)
(*   inserts the seed and the personalization string before anything       *)
(*   else. esdm_es_mgr_reinitialize() does not: after "reinit" a pool has  *)
(*   no state until the next insert.                                       *)
(* - The callers that trigger a seeding after an insert                    *)
(*   (esdm_es_add_entropy()) are left out: they run after the pool lock is *)
(*   dropped. The seedings are processes of their own, each one            *)
(*   esdm_get_seed_buffers() of a DRNG, which holds the DRNG lock or none; *)
(*   nothing takes a lock under a pool lock.                               *)
(* - Of the shared memory status, the need flag alone is modelled, where   *)
(*   Publish says so: esdm_shm_status_set_need_entropy() evaluates         *)
(*   esdm_need_entropy() under its lock and stores the result. It is       *)
(*   called by the operations as the code calls it, a seeding through      *)
(*   esdm_writer_wakeup(), the setter of the threshold since its fix       *)
(*   (WakePublishes). The semaphores and the waiters are the subject       *)
(*   of EsdmShmStatus; the second, unlocked evaluation of                  *)
(*   esdm_writer_wakeup() is a reader as the processes Readers are.        *)
(* - esdm_pool_set_entropy() is called with 0 only (RNDCLEARPOOL,          *)
(*   esdm_aux_reset()), as every caller in the tree does; esdm_aux_fini()  *)
(*   and allocation failures are left out.                                 *)
(* - force_fips may flip at any time where Flips > 0                       *)
(*   (esdm_config_force_fips_set()), switching the oversampling. The flip  *)
(*   publishes nothing, as in the code.                                    *)
(* - esdm_need_entropy() reads its operands in the order of the source:    *)
(*   per pool the count and the oversampling, then the threshold, then the *)
(*   pool size. C leaves the order of the operands of the comparison       *)
(*   open.                                                                 *)
(* - Writers, seeders and readers run a bounded number of operations and   *)
(*   end in "Done"; every process is weakly fair, which suffices as a lock *)
(*   is taken a bounded number of times.                                   *)
(*                                                                         *)
(* The translation is extended below it by the history variable win,       *)
(* which records per evaluation of the need what held while it ran. It is  *)
(* updated from the state after every step of any process, in FullNext:    *)
(* the specification to check is FullSpec.                                 *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    NP,         \* ESDM_NUM_AUX_POOLS
    Cap,        \* esdm_get_digestsize(), entropy units
    OsrU,       \* ESDM_OVERSAMPLE_ES_BITS, entropy units
    OsrInit,    \* esdm_es_oversampling() at start
    Flips,      \* how often force_fips flips
    Writers,    \* processes inserting and crediting
    WOps,       \* what they do: "ins", "stir", "add", "clear", "reinit",
                \* "wake" (esdm_set_write_wakeup_bits())
    Credits,    \* entropy_bits of "ins" and "add", entropy units
    WakeVals,   \* the thresholds "wake" asks for, entropy units
    MaxOps,     \* operations per writer
    Seeders,    \* seedings collecting from the aux source at once
    SeedReqs,   \* their requested_bits, entropy units
    MaxSeeds,   \* collections per seeder
    Readers,    \* threads evaluating esdm_need_entropy() on their own
    MaxReads,   \* evaluations per reader
    Publish,    \* the operations publish the need as the code does
    XofFail,    \* the XOF may fail on an insert or an extraction
    ThreshPerIter, \* esdm_aux_get_backtrack() evaluates its threshold per
                   \* pool, as the code did before its fix
    \* the fixes, FALSE for the code before them:
    WakePublishes, \* esdm_set_write_wakeup_bits() publishes the need
    RawRoom,    \* esdm_pool_insert_aux() measures the room of a pool by the
                \* raw count
    OsrOnce,    \* esdm_aux_get_pool() reads the oversampling once
    WakeCapRead, \* esdm_need_entropy() caps the threshold when it reads it
    AddNeedsState, \* esdm_pool_add_entropy() credits a pool only while its
                   \* XDRBG holds a state
    FailPublishes  \* esdm_pool_insert_aux() publishes the need when the
                   \* insert failed and discarded the credit of the pool

Pools == 0..NP-1
NoProc == "none"
EnvProcs == IF Flips > 0 THEN {"env"} ELSE {}
AllProcs == Writers \cup Seeders \cup Readers \cup EnvProcs

ASSUME WakeVals \subseteq 1..NP * Cap

Min(a, b) == IF a < b THEN a ELSE b
RECURSIVE SumF(_, _)
SumF(f, S) == IF S = {} THEN 0
              ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumF(f, S \ {x})
\* esdm_reduce_by_osr() with the oversampling o
Red(c, o) == IF c >= o THEN c - o ELSE 0
\* esdm_pool_add_entropy_pool()
AddCap(c, e) == IF e > Cap - Min(c, Cap) THEN Cap ELSE Min(c + e, Cap)
XofOK == IF XofFail THEN BOOLEAN ELSE {TRUE}

(* --algorithm EsdmAuxPool {
variables
    count = [p \in Pools |-> 0],        \* aux_entropy_bits
    seeded = [p \in Pools |-> TRUE],    \* xdrbg.seed_initialized
    lock = [p \in Pools |-> NoProc],    \* pool->lock
    osrOn = OsrInit,                    \* force_fips
    \* esdm_write_wakeup_bits, as esdm_set_wakeup_bits() starts it
    wakeup = NP * Red(Cap, IF OsrInit THEN OsrU ELSE 0),
    needLock = NoProc,                  \* esdm_shm_need_lock
    \* status->need_entropy, as esdm_aux_init() publishes it at start
    needPub = NP * Red(Cap, IF OsrInit THEN OsrU ELSE 0) > 0,
    \* the value an evaluation of esdm_need_entropy() returned, until its
    \* caller used it
    nres = [p \in AllProcs |-> FALSE],
    \* ghosts: credit accepted, handed out, and lost to the cap, to a
    \* failing XOF, to clearing and to the oversampling; properties violated
    inTot = 0,
    outTot = 0,
    capLoss = 0,
    failLoss = 0,
    clearLoss = 0,
    osrLoss = 0,
    \* ghost: the pool was emptied as a whole - cleared, re-initialized or
    \* its state discarded - and not credited since
    emptied = [p \in Pools |-> TRUE],
    viol = {};

define {
    Osr == IF osrOn THEN OsrU ELSE 0
    \* esdm_aux_avail_entropy_pool()
    Avail(c) == Red(Min(Cap, c), Osr)
    \* The room of a pool as esdm_pool_insert_aux() measures it
    Room(c) == Cap - (IF RawRoom THEN Min(Cap, c) ELSE Avail(c))
    \* esdm_aux_max_entropy(), esdm_avail_poolsize_aux()
    MaxEnt == NP * Red(Cap, Osr)
}

\* esdm_need_entropy(): esdm_get_aux_ent() sums up the pools, reading per
\* pool the count and then the oversampling; then the threshold is read and
\* capped at the pool size, which reads the oversampling once more. Nothing
\* is locked. The result is left in nres for the caller.
procedure need()
    variables ni = 0, ncnt = 0, nsum = 0, nwk = 0;
{
nd1: while (ni < NP) {
         ncnt := Min(Cap, count[ni]);
nd2:     nsum := nsum + Red(ncnt, Osr);
         ncnt := 0;
         ni := ni + 1;
     };
nd3: nwk := wakeup;
nd4: nres[self] := nsum < (IF WakeCapRead THEN Min(nwk, MaxEnt) ELSE nwk);
     return;
}

\* esdm_shm_status_set_need_entropy(): evaluate the need and store it, under
\* esdm_shm_need_lock
procedure publish()
{
pb1: await needLock = NoProc;
     needLock := self;
     call need();
pb2: needPub := nres[self];
     nres[self] := FALSE;
     needLock := NoProc;
     return;
}

\* esdm_pool_insert_aux() with entropy: select the pool with the most room,
\* or the first one that takes all, reading the counts unlocked; insert
\* under its lock (esdm_aux_pool_insert_locked()); publish the need
procedure insert(ie)
    variables ii = 0, maxRoom = 0, sel = 0;
{
is1: while (ii < NP) {
         with (room = Room(count[ii])) {
             if (maxRoom < room) {
                 maxRoom := room;
                 sel := ii;
             };
             if (ie < room) ii := NP else ii := ii + 1;
         };
     };
is2: await lock[sel] = NoProc;
     with (ok \in XofOK, nc = AddCap(count[sel], ie)) {
         inTot := inTot + ie;
         if (ok) {
             \* lost to the cap while another pool had room for it all
             if (nc - count[sel] < ie /\
                 \E q \in Pools \ {sel} :
                     lock[q] = NoProc /\ Cap - count[q] >= ie)
                 viol := viol \cup {"LossWithRoom"};
             capLoss := capLoss + ie - (nc - count[sel]);
             count[sel] := nc;
             seeded[sel] := TRUE;
             emptied[sel] := FALSE;
         } else {
             failLoss := failLoss + count[sel] + ie;
             count[sel] := 0;
             seeded[sel] := FALSE;
             emptied[sel] := TRUE;
         };
         if (Publish /\ (ok \/ FailPublishes)) {
             call publish();
             return;
         } else {
             return;
         };
     };
}

\* esdm_pool_insert_aux() without entropy: stir every pool, stopping at the
\* first failure. Nothing is published unless a pool lost its credit.
procedure stir()
    variables si = 0, sfail = FALSE;
{
st1: while (si < NP) {
         await lock[si] = NoProc;
         with (ok \in XofOK) {
             if (ok) {
                 seeded[si] := TRUE;
                 si := si + 1;
             } else {
                 failLoss := failLoss + count[si];
                 count[si] := 0;
                 seeded[si] := FALSE;
                 emptied[si] := TRUE;
                 si := NP;
                 sfail := TRUE;
             };
         };
     };
     if (Publish /\ sfail /\ FailPublishes) {
         call publish();
         return;
     } else {
         return;
     };
}

\* esdm_pool_add_entropy(): RNDADDTOENTCNT credits the data of the first
\* pool - where it holds any: a pool whose state was discarded or replaced
\* has no data to credit. Without a credit nothing is published.
procedure add(ae)
{
ad1: await lock[0] = NoProc;
     if (seeded[0] \/ ~AddNeedsState) {
         with (nc = AddCap(count[0], ae)) {
             inTot := inTot + ae;
             capLoss := capLoss + ae - (nc - count[0]);
             count[0] := nc;
             emptied[0] := FALSE;
         };
         if (Publish) {
             call publish();
             return;
         } else {
             return;
         };
     } else {
         return;
     };
}

\* esdm_pool_set_entropy(0): RNDCLEARPOOL, every pool under its lock
procedure clear()
    variables ci = 0;
{
cl1: while (ci < NP) {
         await lock[ci] = NoProc;
         clearLoss := clearLoss + count[ci];
         count[ci] := 0;
         emptied[ci] := TRUE;
         ci := ci + 1;
     };
     if (Publish) {
         call publish();
         return;
     } else {
         return;
     };
}

\* esdm_set_write_wakeup_bits(): the pool size is read, then the threshold
\* stored, capped at it, and the need published, which the threshold is one
\* side of
procedure wake(wv)
    variables wm = 0;
{
wk1: wm := MaxEnt;
wk2: wakeup := Min(wv, wm);
     if (Publish /\ WakePublishes) {
         call publish();
         return;
     } else {
         return;
     };
}

\* esdm_aux_init() as the reinit callback: a new XOF context and a zero
\* count, under the pool lock; then esdm_set_wakeup_bits(), which reads the
\* oversampling and stores the threshold, and the need is published
procedure reinit()
    variables ri = 0, rm = 0;
{
ri1: while (ri < NP) {
         await lock[ri] = NoProc;
         clearLoss := clearLoss + count[ri];
         count[ri] := 0;
         seeded[ri] := FALSE;
         emptied[ri] := TRUE;
         ri := ri + 1;
     };
ri2: rm := Red(Cap, Osr);
ri3: wakeup := NP * rm;
     if (Publish) {
         call publish();
         return;
     } else {
         return;
     };
}

\* esdm_aux_get_backtrack(): look the pools over, each under its lock,
\* keeping the lock of the first one that satisfies the request, else lock
\* the one with the most entropy again; extract from it
\* (esdm_aux_get_pool()). The caller, esdm_fill_seed_buffer(), publishes the
\* need afterwards (esdm_writer_wakeup()).
procedure extract(rq)
    variables ei = 0, maxEnt = 0, pwm = 0, held = FALSE, thr = 0,
              r = 0, o = 0, coll = 0;
{
ex0: thr := rq + Osr;
ex1: while (ei < NP) {
         await lock[ei] = NoProc;
         with (av = Avail(count[ei]),
               m = IF maxEnt < av THEN av ELSE maxEnt,
               t = IF ThreshPerIter THEN rq + Osr ELSE thr) {
             if (maxEnt < av) pwm := ei;
             maxEnt := m;
             if (t <= m) {
                 lock[ei] := self;
                 held := TRUE;
                 ei := NP;
             } else {
                 ei := ei + 1;
             };
         };
     };
ex2: if (~held) {
         await lock[pwm] = NoProc;
         lock[pwm] := self;
     };
     \* drain the count: atomic_exchange()
ex3: viol := viol
         \cup (IF lock[pwm] # self THEN {"ExtractUnlocked"} ELSE {})
         \* the pool looked up is the one extracted from
         \cup (IF \E q \in Pools : lock[q] \in {NoProc, self} /\
                                   Avail(count[q]) > Avail(count[pwm]) /\
                                   Avail(count[pwm]) < thr
               THEN {"MaxAtExtract"} ELSE {});
     if (~seeded[pwm]) {
         goto ex6;
     } else {
         r := Min(rq, Cap);
         o := Osr;
         coll := Min(Cap, count[pwm]);
         count[pwm] := 0;
     };
     \* put the overflow back: atomic_fetch_add()
ex4: if (coll > r + o) {
         count[pwm] := count[pwm] + coll - (r + o);
         coll := r + o;
     };
     \* discount the oversampling, read once more unless OsrOnce
ex5: with (red = Red(coll, IF OsrOnce THEN o ELSE Osr), ok \in XofOK) {
         if (ok) {
             outTot := outTot + red;
             osrLoss := osrLoss + coll - red;
             \* never more credit than bits of output, requested_bits
             if (red > r) viol := viol \cup {"OverOutput"};
         } else {
             \* esdm_xdrbg_extract() failed: the state and its credit go
             failLoss := failLoss + count[pwm] + coll;
             count[pwm] := 0;
             seeded[pwm] := FALSE;
             emptied[pwm] := TRUE;
         };
         coll := 0;
     };
ex6: if (lock[pwm] = self) {
         lock[pwm] := NoProc;
     } else {
         viol := viol \cup {"UnlockOwned"};
     };
     if (Publish) {
         call publish();
         return;
     } else {
         return;
     };
}

fair process (w \in Writers)
    variables nw = 0;
{
wr0: while (nw < MaxOps) {
         nw := nw + 1;
         with (op \in WOps) {
             if (op = "ins") {
                 with (cr \in Credits) call insert(cr);
             } else if (op = "stir") {
                 call stir();
             } else if (op = "add") {
                 with (cr \in Credits) call add(cr);
             } else if (op = "clear") {
                 call clear();
             } else if (op = "wake") {
                 with (v \in WakeVals) call wake(v);
             } else {
                 call reinit();
             };
         };
     };
}

fair process (s \in Seeders)
    variables ns = 0;
{
sd0: while (ns < MaxSeeds) {
         ns := ns + 1;
         with (q \in SeedReqs) call extract(q);
     };
}

\* A thread that evaluates the need on its own: esdm_writer_wakeup() for the
\* writers blocked in the process, the status calls
fair process (rd \in Readers)
    variables nr = 0;
{
rd0: while (nr < MaxReads) {
         nr := nr + 1;
         call need();
rd1:     nres[self] := FALSE;
     };
}

fair process (en \in EnvProcs)
    variables nf = 0;
{
en0: while (nf < Flips) {
         nf := nf + 1;
         osrOn := ~osrOn;
     };
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES count, seeded, lock, osrOn, wakeup, needLock, needPub, nres, inTot, 
          outTot, capLoss, failLoss, clearLoss, osrLoss, emptied, viol, pc, 
          stack

(* define statement *)
Osr == IF osrOn THEN OsrU ELSE 0

Avail(c) == Red(Min(Cap, c), Osr)

Room(c) == Cap - (IF RawRoom THEN Min(Cap, c) ELSE Avail(c))

MaxEnt == NP * Red(Cap, Osr)

VARIABLES ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
          wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, coll, nw, ns, nr, 
          nf

vars == << count, seeded, lock, osrOn, wakeup, needLock, needPub, nres, inTot, 
           outTot, capLoss, failLoss, clearLoss, osrLoss, emptied, viol, pc, 
           stack, ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, ae, 
           ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, coll, nw, 
           ns, nr, nf >>

ProcSet == (Writers) \cup (Seeders) \cup (Readers) \cup (EnvProcs)

Init == (* Global variables *)
        /\ count = [p \in Pools |-> 0]
        /\ seeded = [p \in Pools |-> TRUE]
        /\ lock = [p \in Pools |-> NoProc]
        /\ osrOn = OsrInit
        /\ wakeup = NP * Red(Cap, IF OsrInit THEN OsrU ELSE 0)
        /\ needLock = NoProc
        /\ needPub = (NP * Red(Cap, IF OsrInit THEN OsrU ELSE 0) > 0)
        /\ nres = [p \in AllProcs |-> FALSE]
        /\ inTot = 0
        /\ outTot = 0
        /\ capLoss = 0
        /\ failLoss = 0
        /\ clearLoss = 0
        /\ osrLoss = 0
        /\ emptied = [p \in Pools |-> TRUE]
        /\ viol = {}
        (* Procedure need *)
        /\ ni = [ self \in ProcSet |-> 0]
        /\ ncnt = [ self \in ProcSet |-> 0]
        /\ nsum = [ self \in ProcSet |-> 0]
        /\ nwk = [ self \in ProcSet |-> 0]
        (* Procedure insert *)
        /\ ie = [ self \in ProcSet |-> defaultInitValue]
        /\ ii = [ self \in ProcSet |-> 0]
        /\ maxRoom = [ self \in ProcSet |-> 0]
        /\ sel = [ self \in ProcSet |-> 0]
        (* Procedure stir *)
        /\ si = [ self \in ProcSet |-> 0]
        /\ sfail = [ self \in ProcSet |-> FALSE]
        (* Procedure add *)
        /\ ae = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure clear *)
        /\ ci = [ self \in ProcSet |-> 0]
        (* Procedure wake *)
        /\ wv = [ self \in ProcSet |-> defaultInitValue]
        /\ wm = [ self \in ProcSet |-> 0]
        (* Procedure reinit *)
        /\ ri = [ self \in ProcSet |-> 0]
        /\ rm = [ self \in ProcSet |-> 0]
        (* Procedure extract *)
        /\ rq = [ self \in ProcSet |-> defaultInitValue]
        /\ ei = [ self \in ProcSet |-> 0]
        /\ maxEnt = [ self \in ProcSet |-> 0]
        /\ pwm = [ self \in ProcSet |-> 0]
        /\ held = [ self \in ProcSet |-> FALSE]
        /\ thr = [ self \in ProcSet |-> 0]
        /\ r = [ self \in ProcSet |-> 0]
        /\ o = [ self \in ProcSet |-> 0]
        /\ coll = [ self \in ProcSet |-> 0]
        (* Process w *)
        /\ nw = [self \in Writers |-> 0]
        (* Process s *)
        /\ ns = [self \in Seeders |-> 0]
        (* Process rd *)
        /\ nr = [self \in Readers |-> 0]
        (* Process en *)
        /\ nf = [self \in EnvProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Writers -> "wr0"
                                        [] self \in Seeders -> "sd0"
                                        [] self \in Readers -> "rd0"
                                        [] self \in EnvProcs -> "en0"]

nd1(self) == /\ pc[self] = "nd1"
             /\ IF ni[self] < NP
                   THEN /\ ncnt' = [ncnt EXCEPT ![self] = Min(Cap, count[ni[self]])]
                        /\ pc' = [pc EXCEPT ![self] = "nd2"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "nd3"]
                        /\ ncnt' = ncnt
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             nsum, nwk, ie, ii, maxRoom, sel, si, sfail, ae, 
                             ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, 
                             thr, r, o, coll, nw, ns, nr, nf >>

nd2(self) == /\ pc[self] = "nd2"
             /\ nsum' = [nsum EXCEPT ![self] = nsum[self] + Red(ncnt[self], Osr)]
             /\ ncnt' = [ncnt EXCEPT ![self] = 0]
             /\ ni' = [ni EXCEPT ![self] = ni[self] + 1]
             /\ pc' = [pc EXCEPT ![self] = "nd1"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, nwk, ie, 
                             ii, maxRoom, sel, si, sfail, ae, ci, wv, wm, ri, 
                             rm, rq, ei, maxEnt, pwm, held, thr, r, o, coll, 
                             nw, ns, nr, nf >>

nd3(self) == /\ pc[self] = "nd3"
             /\ nwk' = [nwk EXCEPT ![self] = wakeup]
             /\ pc' = [pc EXCEPT ![self] = "nd4"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, ie, ii, maxRoom, sel, si, sfail, ae, 
                             ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, 
                             thr, r, o, coll, nw, ns, nr, nf >>

nd4(self) == /\ pc[self] = "nd4"
             /\ nres' = [nres EXCEPT ![self] = nsum[self] < (IF WakeCapRead THEN Min(nwk[self], MaxEnt) ELSE nwk[self])]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ni' = [ni EXCEPT ![self] = Head(stack[self]).ni]
             /\ ncnt' = [ncnt EXCEPT ![self] = Head(stack[self]).ncnt]
             /\ nsum' = [nsum EXCEPT ![self] = Head(stack[self]).nsum]
             /\ nwk' = [nwk EXCEPT ![self] = Head(stack[self]).nwk]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, ie, ii, 
                             maxRoom, sel, si, sfail, ae, ci, wv, wm, ri, rm, 
                             rq, ei, maxEnt, pwm, held, thr, r, o, coll, nw, 
                             ns, nr, nf >>

need(self) == nd1(self) \/ nd2(self) \/ nd3(self) \/ nd4(self)

pb1(self) == /\ pc[self] = "pb1"
             /\ needLock = NoProc
             /\ needLock' = self
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "need",
                                                      pc        |->  "pb2",
                                                      ni        |->  ni[self],
                                                      ncnt      |->  ncnt[self],
                                                      nsum      |->  nsum[self],
                                                      nwk       |->  nwk[self] ] >>
                                                  \o stack[self]]
             /\ ni' = [ni EXCEPT ![self] = 0]
             /\ ncnt' = [ncnt EXCEPT ![self] = 0]
             /\ nsum' = [nsum EXCEPT ![self] = 0]
             /\ nwk' = [nwk EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "nd1"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needPub, nres, 
                             inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, ie, ii, maxRoom, sel, si, 
                             sfail, ae, ci, wv, wm, ri, rm, rq, ei, maxEnt, 
                             pwm, held, thr, r, o, coll, nw, ns, nr, nf >>

pb2(self) == /\ pc[self] = "pb2"
             /\ needPub' = nres[self]
             /\ nres' = [nres EXCEPT ![self] = FALSE]
             /\ needLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, emptied, 
                             viol, ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, 
                             si, sfail, ae, ci, wv, wm, ri, rm, rq, ei, maxEnt, 
                             pwm, held, thr, r, o, coll, nw, ns, nr, nf >>

publish(self) == pb1(self) \/ pb2(self)

is1(self) == /\ pc[self] = "is1"
             /\ IF ii[self] < NP
                   THEN /\ LET room == Room(count[ii[self]]) IN
                             /\ IF maxRoom[self] < room
                                   THEN /\ maxRoom' = [maxRoom EXCEPT ![self] = room]
                                        /\ sel' = [sel EXCEPT ![self] = ii[self]]
                                   ELSE /\ TRUE
                                        /\ UNCHANGED << maxRoom, sel >>
                             /\ IF ie[self] < room
                                   THEN /\ ii' = [ii EXCEPT ![self] = NP]
                                   ELSE /\ ii' = [ii EXCEPT ![self] = ii[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "is1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "is2"]
                        /\ UNCHANGED << ii, maxRoom, sel >>
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, nwk, ie, si, sfail, ae, ci, wv, wm, 
                             ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             coll, nw, ns, nr, nf >>

is2(self) == /\ pc[self] = "is2"
             /\ lock[sel[self]] = NoProc
             /\ \E ok \in XofOK:
                  LET nc == AddCap(count[sel[self]], ie[self]) IN
                    /\ inTot' = inTot + ie[self]
                    /\ IF ok
                          THEN /\ IF nc - count[sel[self]] < ie[self] /\
                                     \E q \in Pools \ {sel[self]} :
                                         lock[q] = NoProc /\ Cap - count[q] >= ie[self]
                                     THEN /\ viol' = (viol \cup {"LossWithRoom"})
                                     ELSE /\ TRUE
                                          /\ viol' = viol
                               /\ capLoss' = capLoss + ie[self] - (nc - count[sel[self]])
                               /\ count' = [count EXCEPT ![sel[self]] = nc]
                               /\ seeded' = [seeded EXCEPT ![sel[self]] = TRUE]
                               /\ emptied' = [emptied EXCEPT ![sel[self]] = FALSE]
                               /\ UNCHANGED failLoss
                          ELSE /\ failLoss' = failLoss + count[sel[self]] + ie[self]
                               /\ count' = [count EXCEPT ![sel[self]] = 0]
                               /\ seeded' = [seeded EXCEPT ![sel[self]] = FALSE]
                               /\ emptied' = [emptied EXCEPT ![sel[self]] = TRUE]
                               /\ UNCHANGED << capLoss, viol >>
                    /\ IF Publish /\ (ok \/ FailPublishes)
                          THEN /\ /\ ii' = [ii EXCEPT ![self] = Head(stack[self]).ii]
                                  /\ maxRoom' = [maxRoom EXCEPT ![self] = Head(stack[self]).maxRoom]
                                  /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
                                  /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                           pc        |->  Head(stack[self]).pc ] >>
                                                                       \o Tail(stack[self])]
                               /\ pc' = [pc EXCEPT ![self] = "pb1"]
                               /\ ie' = ie
                          ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                               /\ ii' = [ii EXCEPT ![self] = Head(stack[self]).ii]
                               /\ maxRoom' = [maxRoom EXCEPT ![self] = Head(stack[self]).maxRoom]
                               /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
                               /\ ie' = [ie EXCEPT ![self] = Head(stack[self]).ie]
                               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << lock, osrOn, wakeup, needLock, needPub, nres, 
                             outTot, clearLoss, osrLoss, ni, ncnt, nsum, nwk, 
                             si, sfail, ae, ci, wv, wm, ri, rm, rq, ei, maxEnt, 
                             pwm, held, thr, r, o, coll, nw, ns, nr, nf >>

insert(self) == is1(self) \/ is2(self)

st1(self) == /\ pc[self] = "st1"
             /\ IF si[self] < NP
                   THEN /\ lock[si[self]] = NoProc
                        /\ \E ok \in XofOK:
                             IF ok
                                THEN /\ seeded' = [seeded EXCEPT ![si[self]] = TRUE]
                                     /\ si' = [si EXCEPT ![self] = si[self] + 1]
                                     /\ UNCHANGED << count, failLoss, emptied, 
                                                     sfail >>
                                ELSE /\ failLoss' = failLoss + count[si[self]]
                                     /\ count' = [count EXCEPT ![si[self]] = 0]
                                     /\ seeded' = [seeded EXCEPT ![si[self]] = FALSE]
                                     /\ emptied' = [emptied EXCEPT ![si[self]] = TRUE]
                                     /\ si' = [si EXCEPT ![self] = NP]
                                     /\ sfail' = [sfail EXCEPT ![self] = TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "st1"]
                        /\ stack' = stack
                   ELSE /\ IF Publish /\ sfail[self] /\ FailPublishes
                              THEN /\ /\ sfail' = [sfail EXCEPT ![self] = Head(stack[self]).sfail]
                                      /\ si' = [si EXCEPT ![self] = Head(stack[self]).si]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                               pc        |->  Head(stack[self]).pc ] >>
                                                                           \o Tail(stack[self])]
                                   /\ pc' = [pc EXCEPT ![self] = "pb1"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ si' = [si EXCEPT ![self] = Head(stack[self]).si]
                                   /\ sfail' = [sfail EXCEPT ![self] = Head(stack[self]).sfail]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << count, seeded, failLoss, emptied >>
             /\ UNCHANGED << lock, osrOn, wakeup, needLock, needPub, nres, 
                             inTot, outTot, capLoss, clearLoss, osrLoss, viol, 
                             ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, ae, ci, 
                             wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, 
                             o, coll, nw, ns, nr, nf >>

stir(self) == st1(self)

ad1(self) == /\ pc[self] = "ad1"
             /\ lock[0] = NoProc
             /\ IF seeded[0] \/ ~AddNeedsState
                   THEN /\ LET nc == AddCap(count[0], ae[self]) IN
                             /\ inTot' = inTot + ae[self]
                             /\ capLoss' = capLoss + ae[self] - (nc - count[0])
                             /\ count' = [count EXCEPT ![0] = nc]
                             /\ emptied' = [emptied EXCEPT ![0] = FALSE]
                        /\ IF Publish
                              THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                            pc        |->  Head(stack[self]).pc ] >>
                                                                        \o Tail(stack[self])]
                                   /\ pc' = [pc EXCEPT ![self] = "pb1"]
                                   /\ ae' = ae
                              ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ ae' = [ae EXCEPT ![self] = Head(stack[self]).ae]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ ae' = [ae EXCEPT ![self] = Head(stack[self]).ae]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << count, inTot, capLoss, emptied >>
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, needLock, needPub, 
                             nres, outTot, failLoss, clearLoss, osrLoss, viol, 
                             ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, 
                             sfail, ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, 
                             held, thr, r, o, coll, nw, ns, nr, nf >>

add(self) == ad1(self)

cl1(self) == /\ pc[self] = "cl1"
             /\ IF ci[self] < NP
                   THEN /\ lock[ci[self]] = NoProc
                        /\ clearLoss' = clearLoss + count[ci[self]]
                        /\ count' = [count EXCEPT ![ci[self]] = 0]
                        /\ emptied' = [emptied EXCEPT ![ci[self]] = TRUE]
                        /\ ci' = [ci EXCEPT ![self] = ci[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "cl1"]
                        /\ stack' = stack
                   ELSE /\ IF Publish
                              THEN /\ /\ ci' = [ci EXCEPT ![self] = Head(stack[self]).ci]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                               pc        |->  Head(stack[self]).pc ] >>
                                                                           \o Tail(stack[self])]
                                   /\ pc' = [pc EXCEPT ![self] = "pb1"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ ci' = [ci EXCEPT ![self] = Head(stack[self]).ci]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << count, clearLoss, emptied >>
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, osrLoss, 
                             viol, ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, 
                             si, sfail, ae, wv, wm, ri, rm, rq, ei, maxEnt, 
                             pwm, held, thr, r, o, coll, nw, ns, nr, nf >>

clear(self) == cl1(self)

wk1(self) == /\ pc[self] = "wk1"
             /\ wm' = [wm EXCEPT ![self] = MaxEnt]
             /\ pc' = [pc EXCEPT ![self] = "wk2"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, 
                             ae, ci, wv, ri, rm, rq, ei, maxEnt, pwm, held, 
                             thr, r, o, coll, nw, ns, nr, nf >>

wk2(self) == /\ pc[self] = "wk2"
             /\ wakeup' = Min(wv[self], wm[self])
             /\ IF Publish /\ WakePublishes
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                    pc        |->  Head(stack[self]).pc ] >>
                                                                \o Tail(stack[self])]
                           /\ wm' = [wm EXCEPT ![self] = Head(stack[self]).wm]
                        /\ pc' = [pc EXCEPT ![self] = "pb1"]
                        /\ wv' = wv
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ wm' = [wm EXCEPT ![self] = Head(stack[self]).wm]
                        /\ wv' = [wv EXCEPT ![self] = Head(stack[self]).wv]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, lock, osrOn, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, ni, ncnt, nsum, nwk, ie, 
                             ii, maxRoom, sel, si, sfail, ae, ci, ri, rm, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, coll, nw, ns, 
                             nr, nf >>

wake(self) == wk1(self) \/ wk2(self)

ri1(self) == /\ pc[self] = "ri1"
             /\ IF ri[self] < NP
                   THEN /\ lock[ri[self]] = NoProc
                        /\ clearLoss' = clearLoss + count[ri[self]]
                        /\ count' = [count EXCEPT ![ri[self]] = 0]
                        /\ seeded' = [seeded EXCEPT ![ri[self]] = FALSE]
                        /\ emptied' = [emptied EXCEPT ![ri[self]] = TRUE]
                        /\ ri' = [ri EXCEPT ![self] = ri[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "ri1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ri2"]
                        /\ UNCHANGED << count, seeded, clearLoss, emptied, ri >>
             /\ UNCHANGED << lock, osrOn, wakeup, needLock, needPub, nres, 
                             inTot, outTot, capLoss, failLoss, osrLoss, viol, 
                             stack, ni, ncnt, nsum, nwk, ie, ii, maxRoom, sel, 
                             si, sfail, ae, ci, wv, wm, rm, rq, ei, maxEnt, 
                             pwm, held, thr, r, o, coll, nw, ns, nr, nf >>

ri2(self) == /\ pc[self] = "ri2"
             /\ rm' = [rm EXCEPT ![self] = Red(Cap, Osr)]
             /\ pc' = [pc EXCEPT ![self] = "ri3"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, 
                             ae, ci, wv, wm, ri, rq, ei, maxEnt, pwm, held, 
                             thr, r, o, coll, nw, ns, nr, nf >>

ri3(self) == /\ pc[self] = "ri3"
             /\ wakeup' = NP * rm[self]
             /\ IF Publish
                   THEN /\ /\ ri' = [ri EXCEPT ![self] = Head(stack[self]).ri]
                           /\ rm' = [rm EXCEPT ![self] = Head(stack[self]).rm]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                    pc        |->  Head(stack[self]).pc ] >>
                                                                \o Tail(stack[self])]
                        /\ pc' = [pc EXCEPT ![self] = "pb1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ ri' = [ri EXCEPT ![self] = Head(stack[self]).ri]
                        /\ rm' = [rm EXCEPT ![self] = Head(stack[self]).rm]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, lock, osrOn, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, ni, ncnt, nsum, nwk, ie, 
                             ii, maxRoom, sel, si, sfail, ae, ci, wv, wm, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, coll, nw, ns, 
                             nr, nf >>

reinit(self) == ri1(self) \/ ri2(self) \/ ri3(self)

ex0(self) == /\ pc[self] = "ex0"
             /\ thr' = [thr EXCEPT ![self] = rq[self] + Osr]
             /\ pc' = [pc EXCEPT ![self] = "ex1"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, 
                             ae, ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, 
                             r, o, coll, nw, ns, nr, nf >>

ex1(self) == /\ pc[self] = "ex1"
             /\ IF ei[self] < NP
                   THEN /\ lock[ei[self]] = NoProc
                        /\ LET av == Avail(count[ei[self]]) IN
                             LET m == IF maxEnt[self] < av THEN av ELSE maxEnt[self] IN
                               LET t == IF ThreshPerIter THEN rq[self] + Osr ELSE thr[self] IN
                                 /\ IF maxEnt[self] < av
                                       THEN /\ pwm' = [pwm EXCEPT ![self] = ei[self]]
                                       ELSE /\ TRUE
                                            /\ pwm' = pwm
                                 /\ maxEnt' = [maxEnt EXCEPT ![self] = m]
                                 /\ IF t <= m
                                       THEN /\ lock' = [lock EXCEPT ![ei[self]] = self]
                                            /\ held' = [held EXCEPT ![self] = TRUE]
                                            /\ ei' = [ei EXCEPT ![self] = NP]
                                       ELSE /\ ei' = [ei EXCEPT ![self] = ei[self] + 1]
                                            /\ UNCHANGED << lock, held >>
                        /\ pc' = [pc EXCEPT ![self] = "ex1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ex2"]
                        /\ UNCHANGED << lock, ei, maxEnt, pwm, held >>
             /\ UNCHANGED << count, seeded, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, stack, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, rq, thr, r, o, coll, nw, ns, nr, nf >>

ex2(self) == /\ pc[self] = "ex2"
             /\ IF ~held[self]
                   THEN /\ lock[pwm[self]] = NoProc
                        /\ lock' = [lock EXCEPT ![pwm[self]] = self]
                   ELSE /\ TRUE
                        /\ lock' = lock
             /\ pc' = [pc EXCEPT ![self] = "ex3"]
             /\ UNCHANGED << count, seeded, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, stack, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             coll, nw, ns, nr, nf >>

ex3(self) == /\ pc[self] = "ex3"
             /\ viol' =     viol
                        \cup (IF lock[pwm[self]] # self THEN {"ExtractUnlocked"} ELSE {})
                        
                        \cup (IF \E q \in Pools : lock[q] \in {NoProc, self} /\
                                                  Avail(count[q]) > Avail(count[pwm[self]]) /\
                                                  Avail(count[pwm[self]]) < thr[self]
                              THEN {"MaxAtExtract"} ELSE {})
             /\ IF ~seeded[pwm[self]]
                   THEN /\ pc' = [pc EXCEPT ![self] = "ex6"]
                        /\ UNCHANGED << count, r, o, coll >>
                   ELSE /\ r' = [r EXCEPT ![self] = Min(rq[self], Cap)]
                        /\ o' = [o EXCEPT ![self] = Osr]
                        /\ coll' = [coll EXCEPT ![self] = Min(Cap, count[pwm[self]])]
                        /\ count' = [count EXCEPT ![pwm[self]] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "ex4"]
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, stack, ni, ncnt, nsum, nwk, ie, 
                             ii, maxRoom, sel, si, sfail, ae, ci, wv, wm, ri, 
                             rm, rq, ei, maxEnt, pwm, held, thr, nw, ns, nr, 
                             nf >>

ex4(self) == /\ pc[self] = "ex4"
             /\ IF coll[self] > r[self] + o[self]
                   THEN /\ count' = [count EXCEPT ![pwm[self]] = count[pwm[self]] + coll[self] - (r[self] + o[self])]
                        /\ coll' = [coll EXCEPT ![self] = r[self] + o[self]]
                   ELSE /\ TRUE
                        /\ UNCHANGED << count, coll >>
             /\ pc' = [pc EXCEPT ![self] = "ex5"]
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, stack, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             nw, ns, nr, nf >>

ex5(self) == /\ pc[self] = "ex5"
             /\ LET red == Red(coll[self], IF OsrOnce THEN o[self] ELSE Osr) IN
                  \E ok \in XofOK:
                    /\ IF ok
                          THEN /\ outTot' = outTot + red
                               /\ osrLoss' = osrLoss + coll[self] - red
                               /\ IF red > r[self]
                                     THEN /\ viol' = (viol \cup {"OverOutput"})
                                     ELSE /\ TRUE
                                          /\ viol' = viol
                               /\ UNCHANGED << count, seeded, failLoss, 
                                               emptied >>
                          ELSE /\ failLoss' = failLoss + count[pwm[self]] + coll[self]
                               /\ count' = [count EXCEPT ![pwm[self]] = 0]
                               /\ seeded' = [seeded EXCEPT ![pwm[self]] = FALSE]
                               /\ emptied' = [emptied EXCEPT ![pwm[self]] = TRUE]
                               /\ UNCHANGED << outTot, osrLoss, viol >>
                    /\ coll' = [coll EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "ex6"]
             /\ UNCHANGED << lock, osrOn, wakeup, needLock, needPub, nres, 
                             inTot, capLoss, clearLoss, stack, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             nw, ns, nr, nf >>

ex6(self) == /\ pc[self] = "ex6"
             /\ IF lock[pwm[self]] = self
                   THEN /\ lock' = [lock EXCEPT ![pwm[self]] = NoProc]
                        /\ viol' = viol
                   ELSE /\ viol' = (viol \cup {"UnlockOwned"})
                        /\ lock' = lock
             /\ IF Publish
                   THEN /\ /\ coll' = [coll EXCEPT ![self] = Head(stack[self]).coll]
                           /\ ei' = [ei EXCEPT ![self] = Head(stack[self]).ei]
                           /\ held' = [held EXCEPT ![self] = Head(stack[self]).held]
                           /\ maxEnt' = [maxEnt EXCEPT ![self] = Head(stack[self]).maxEnt]
                           /\ o' = [o EXCEPT ![self] = Head(stack[self]).o]
                           /\ pwm' = [pwm EXCEPT ![self] = Head(stack[self]).pwm]
                           /\ r' = [r EXCEPT ![self] = Head(stack[self]).r]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "publish",
                                                                    pc        |->  Head(stack[self]).pc ] >>
                                                                \o Tail(stack[self])]
                           /\ thr' = [thr EXCEPT ![self] = Head(stack[self]).thr]
                        /\ pc' = [pc EXCEPT ![self] = "pb1"]
                        /\ rq' = rq
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ ei' = [ei EXCEPT ![self] = Head(stack[self]).ei]
                        /\ maxEnt' = [maxEnt EXCEPT ![self] = Head(stack[self]).maxEnt]
                        /\ pwm' = [pwm EXCEPT ![self] = Head(stack[self]).pwm]
                        /\ held' = [held EXCEPT ![self] = Head(stack[self]).held]
                        /\ thr' = [thr EXCEPT ![self] = Head(stack[self]).thr]
                        /\ r' = [r EXCEPT ![self] = Head(stack[self]).r]
                        /\ o' = [o EXCEPT ![self] = Head(stack[self]).o]
                        /\ coll' = [coll EXCEPT ![self] = Head(stack[self]).coll]
                        /\ rq' = [rq EXCEPT ![self] = Head(stack[self]).rq]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, osrOn, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, ni, ncnt, nsum, nwk, ie, ii, 
                             maxRoom, sel, si, sfail, ae, ci, wv, wm, ri, rm, 
                             nw, ns, nr, nf >>

extract(self) == ex0(self) \/ ex1(self) \/ ex2(self) \/ ex3(self)
                    \/ ex4(self) \/ ex5(self) \/ ex6(self)

wr0(self) == /\ pc[self] = "wr0"
             /\ IF nw[self] < MaxOps
                   THEN /\ nw' = [nw EXCEPT ![self] = nw[self] + 1]
                        /\ \E op \in WOps:
                             IF op = "ins"
                                THEN /\ \E cr \in Credits:
                                          /\ /\ ie' = [ie EXCEPT ![self] = cr]
                                             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "insert",
                                                                                      pc        |->  "wr0",
                                                                                      ii        |->  ii[self],
                                                                                      maxRoom   |->  maxRoom[self],
                                                                                      sel       |->  sel[self],
                                                                                      ie        |->  ie[self] ] >>
                                                                                  \o stack[self]]
                                          /\ ii' = [ii EXCEPT ![self] = 0]
                                          /\ maxRoom' = [maxRoom EXCEPT ![self] = 0]
                                          /\ sel' = [sel EXCEPT ![self] = 0]
                                          /\ pc' = [pc EXCEPT ![self] = "is1"]
                                     /\ UNCHANGED << si, sfail, ae, ci, wv, wm, 
                                                     ri, rm >>
                                ELSE /\ IF op = "stir"
                                           THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "stir",
                                                                                         pc        |->  "wr0",
                                                                                         si        |->  si[self],
                                                                                         sfail     |->  sfail[self] ] >>
                                                                                     \o stack[self]]
                                                /\ si' = [si EXCEPT ![self] = 0]
                                                /\ sfail' = [sfail EXCEPT ![self] = FALSE]
                                                /\ pc' = [pc EXCEPT ![self] = "st1"]
                                                /\ UNCHANGED << ae, ci, wv, wm, 
                                                                ri, rm >>
                                           ELSE /\ IF op = "add"
                                                      THEN /\ \E cr \in Credits:
                                                                /\ /\ ae' = [ae EXCEPT ![self] = cr]
                                                                   /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "add",
                                                                                                            pc        |->  "wr0",
                                                                                                            ae        |->  ae[self] ] >>
                                                                                                        \o stack[self]]
                                                                /\ pc' = [pc EXCEPT ![self] = "ad1"]
                                                           /\ UNCHANGED << ci, 
                                                                           wv, 
                                                                           wm, 
                                                                           ri, 
                                                                           rm >>
                                                      ELSE /\ IF op = "clear"
                                                                 THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "clear",
                                                                                                               pc        |->  "wr0",
                                                                                                               ci        |->  ci[self] ] >>
                                                                                                           \o stack[self]]
                                                                      /\ ci' = [ci EXCEPT ![self] = 0]
                                                                      /\ pc' = [pc EXCEPT ![self] = "cl1"]
                                                                      /\ UNCHANGED << wv, 
                                                                                      wm, 
                                                                                      ri, 
                                                                                      rm >>
                                                                 ELSE /\ IF op = "wake"
                                                                            THEN /\ \E v \in WakeVals:
                                                                                      /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "wake",
                                                                                                                                  pc        |->  "wr0",
                                                                                                                                  wm        |->  wm[self],
                                                                                                                                  wv        |->  wv[self] ] >>
                                                                                                                              \o stack[self]]
                                                                                         /\ wv' = [wv EXCEPT ![self] = v]
                                                                                      /\ wm' = [wm EXCEPT ![self] = 0]
                                                                                      /\ pc' = [pc EXCEPT ![self] = "wk1"]
                                                                                 /\ UNCHANGED << ri, 
                                                                                                 rm >>
                                                                            ELSE /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reinit",
                                                                                                                          pc        |->  "wr0",
                                                                                                                          ri        |->  ri[self],
                                                                                                                          rm        |->  rm[self] ] >>
                                                                                                                      \o stack[self]]
                                                                                 /\ ri' = [ri EXCEPT ![self] = 0]
                                                                                 /\ rm' = [rm EXCEPT ![self] = 0]
                                                                                 /\ pc' = [pc EXCEPT ![self] = "ri1"]
                                                                                 /\ UNCHANGED << wv, 
                                                                                                 wm >>
                                                                      /\ ci' = ci
                                                           /\ ae' = ae
                                                /\ UNCHANGED << si, sfail >>
                                     /\ UNCHANGED << ie, ii, maxRoom, sel >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, ie, ii, maxRoom, sel, si, sfail, 
                                        ae, ci, wv, wm, ri, rm, nw >>
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, ni, ncnt, nsum, 
                             nwk, rq, ei, maxEnt, pwm, held, thr, r, o, coll, 
                             ns, nr, nf >>

w(self) == wr0(self)

sd0(self) == /\ pc[self] = "sd0"
             /\ IF ns[self] < MaxSeeds
                   THEN /\ ns' = [ns EXCEPT ![self] = ns[self] + 1]
                        /\ \E q \in SeedReqs:
                             /\ /\ rq' = [rq EXCEPT ![self] = q]
                                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "extract",
                                                                         pc        |->  "sd0",
                                                                         ei        |->  ei[self],
                                                                         maxEnt    |->  maxEnt[self],
                                                                         pwm       |->  pwm[self],
                                                                         held      |->  held[self],
                                                                         thr       |->  thr[self],
                                                                         r         |->  r[self],
                                                                         o         |->  o[self],
                                                                         coll      |->  coll[self],
                                                                         rq        |->  rq[self] ] >>
                                                                     \o stack[self]]
                             /\ ei' = [ei EXCEPT ![self] = 0]
                             /\ maxEnt' = [maxEnt EXCEPT ![self] = 0]
                             /\ pwm' = [pwm EXCEPT ![self] = 0]
                             /\ held' = [held EXCEPT ![self] = FALSE]
                             /\ thr' = [thr EXCEPT ![self] = 0]
                             /\ r' = [r EXCEPT ![self] = 0]
                             /\ o' = [o EXCEPT ![self] = 0]
                             /\ coll' = [coll EXCEPT ![self] = 0]
                             /\ pc' = [pc EXCEPT ![self] = "ex0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, rq, ei, maxEnt, pwm, held, thr, 
                                        r, o, coll, ns >>
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, nw, nr, nf >>

s(self) == sd0(self)

rd0(self) == /\ pc[self] = "rd0"
             /\ IF nr[self] < MaxReads
                   THEN /\ nr' = [nr EXCEPT ![self] = nr[self] + 1]
                        /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "need",
                                                                 pc        |->  "rd1",
                                                                 ni        |->  ni[self],
                                                                 ncnt      |->  ncnt[self],
                                                                 nsum      |->  nsum[self],
                                                                 nwk       |->  nwk[self] ] >>
                                                             \o stack[self]]
                        /\ ni' = [ni EXCEPT ![self] = 0]
                        /\ ncnt' = [ncnt EXCEPT ![self] = 0]
                        /\ nsum' = [nsum EXCEPT ![self] = 0]
                        /\ nwk' = [nwk EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "nd1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, ni, ncnt, nsum, nwk, nr >>
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, nres, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, ie, ii, 
                             maxRoom, sel, si, sfail, ae, ci, wv, wm, ri, rm, 
                             rq, ei, maxEnt, pwm, held, thr, r, o, coll, nw, 
                             ns, nf >>

rd1(self) == /\ pc[self] = "rd1"
             /\ nres' = [nres EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "rd0"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, needLock, 
                             needPub, inTot, outTot, capLoss, failLoss, 
                             clearLoss, osrLoss, emptied, viol, stack, ni, 
                             ncnt, nsum, nwk, ie, ii, maxRoom, sel, si, sfail, 
                             ae, ci, wv, wm, ri, rm, rq, ei, maxEnt, pwm, held, 
                             thr, r, o, coll, nw, ns, nr, nf >>

rd(self) == rd0(self) \/ rd1(self)

en0(self) == /\ pc[self] = "en0"
             /\ IF nf[self] < Flips
                   THEN /\ nf' = [nf EXCEPT ![self] = nf[self] + 1]
                        /\ osrOn' = ~osrOn
                        /\ pc' = [pc EXCEPT ![self] = "en0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << osrOn, nf >>
             /\ UNCHANGED << count, seeded, lock, wakeup, needLock, needPub, 
                             nres, inTot, outTot, capLoss, failLoss, clearLoss, 
                             osrLoss, emptied, viol, stack, ni, ncnt, nsum, 
                             nwk, ie, ii, maxRoom, sel, si, sfail, ae, ci, wv, 
                             wm, ri, rm, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             coll, nw, ns, nr >>

en(self) == en0(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in ProcSet:  \/ need(self) \/ publish(self)
                               \/ insert(self) \/ stir(self) \/ add(self)
                               \/ clear(self) \/ wake(self) \/ reinit(self)
                               \/ extract(self))
           \/ (\E self \in Writers: w(self))
           \/ (\E self \in Seeders: s(self))
           \/ (\E self \in Readers: rd(self))
           \/ (\E self \in EnvProcs: en(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Writers : /\ WF_vars(w(self))
                                 /\ WF_vars(insert(self))
                                 /\ WF_vars(stir(self))
                                 /\ WF_vars(add(self))
                                 /\ WF_vars(clear(self))
                                 /\ WF_vars(wake(self))
                                 /\ WF_vars(reinit(self))
                                 /\ WF_vars(need(self))
                                 /\ WF_vars(publish(self))
        /\ \A self \in Seeders : /\ WF_vars(s(self))
                                 /\ WF_vars(extract(self))
                                 /\ WF_vars(need(self))
                                 /\ WF_vars(publish(self))
        /\ \A self \in Readers : WF_vars(rd(self)) /\ WF_vars(need(self))
        /\ \A self \in EnvProcs : WF_vars(en(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* The history of an evaluation of the need *)

\* esdm_need_entropy() as a function of the state: what an evaluation
\* returns that no step of another thread overlaps
Need == SumF([p \in Pools |-> Avail(count[p])], Pools)
            < (IF WakeCapRead THEN Min(wakeup, MaxEnt) ELSE wakeup)
AllFull == \A p \in Pools : count[p] = Cap

NeedLabels == {"nd1", "nd2", "nd3", "nd4"}
\* where the caller of an evaluation holds its result
AfterLabels == {"pb2", "rd1"}

\* Per process, for the evaluation it runs or has just finished, over the
\* states from its call to its return: every pool was full in all of them
\* (full); force_fips (fips) and the threshold (thr) did not change; the
\* need held in one of them (ever), in all of them (always).
VARIABLE win
varsG == << vars, win >>

WinIdle == [full |-> FALSE, fips |-> FALSE, thr |-> FALSE,
            ever |-> FALSE, always |-> FALSE]
WinOpen == [full |-> AllFull', fips |-> TRUE, thr |-> TRUE,
            ever |-> Need', always |-> Need']
WinStep(x) == [full |-> win[x].full /\ AllFull',
               fips |-> win[x].fips /\ osrOn' = osrOn,
               thr |-> win[x].thr /\ wakeup' = wakeup,
               ever |-> win[x].ever \/ Need',
               always |-> win[x].always /\ Need']
\* Not part of any step of the algorithm: computed from the state a step
\* leaves, whichever process took it
WinNext ==
    win' = [x \in AllProcs |->
               IF pc'[x] \in NeedLabels
               THEN IF pc[x] \in NeedLabels THEN WinStep(x) ELSE WinOpen
               ELSE IF pc'[x] \in AfterLabels
                    THEN IF pc[x] \in NeedLabels THEN WinStep(x) ELSE win[x]
                    ELSE WinIdle]

ProcStep(self) ==
    \/ need(self) \/ publish(self) \/ insert(self) \/ stir(self)
    \/ add(self) \/ clear(self) \/ wake(self) \/ reinit(self)
    \/ extract(self)
    \/ (self \in Writers /\ w(self))
    \/ (self \in Seeders /\ s(self))
    \/ (self \in Readers /\ rd(self))
    \/ (self \in EnvProcs /\ en(self))

FullNext == Next /\ WinNext

\* Spec with the history variable. Weak fairness per process: a process is
\* at one label, so this is the fairness of Spec.
FullSpec == /\ Init /\ win = [x \in AllProcs |-> WinIdle]
            /\ [][FullNext]_varsG
            /\ \A self \in AllProcs : WF_varsG(ProcStep(self) /\ WinNext)

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ count \in [Pools -> 0..Cap]
    /\ seeded \in [Pools -> BOOLEAN]
    /\ emptied \in [Pools -> BOOLEAN]
    /\ lock \in [Pools -> AllProcs \cup {NoProc}]
    /\ needLock \in AllProcs \cup {NoProc}
    /\ needPub \in BOOLEAN
    /\ nres \in [AllProcs -> BOOLEAN]
    /\ wakeup \in 0..NP * Cap

\* Credit held by extractions between draining a count and handing it out
InFlight == SumF(coll, AllProcs)

\* Conservation of credit: what the pools hand out and still hold never
\* exceeds what they were credited with. Two extractions never both hand
\* out the same credit.
Conservation == outTot + SumF(count, Pools) + InFlight <= inTot

\* ... and every unit credited is accounted for: handed out, held, or lost
\* to the cap, a failing XOF, clearing or the oversampling.
Accounting ==
    inTot = outTot + SumF(count, Pools) + InFlight
            + capLoss + failLoss + clearLoss + osrLoss

\* The count never exceeds the capacity of a pool.
CountBound == \A p \in Pools : count[p] <= Cap

\* A process holds at most one pool lock: there is no lock order to keep.
\* The lock of the need is taken with no pool lock held, and no pool lock
\* under it.
OneLock == \A p \in AllProcs :
    /\ Cardinality({q \in Pools : lock[q] = p}) <= 1
    /\ needLock = p => \A q \in Pools : lock[q] # p

\* esdm_aux_get_backtrack() extracts from the pool it holds the lock of and
\* releases that lock, the claim of its comment on the threshold.
ExtractLocked == "ExtractUnlocked" \notin viol
UnlockOwned == "UnlockOwned" \notin viol

\* Lookup and extraction are atomic: the pool extracted from has the most
\* entropy, or enough. Its comment claimed so before its fix; it holds for a
\* pool that satisfies the request only.
MaxAtExtract == "MaxAtExtract" \notin viol

\* An extraction credits no more bits than it outputs.
CreditFitsOutput == "OverOutput" \notin viol

\* An insert loses credit to the cap only if no other pool had room for it.
NoLossWithRoom == "LossWithRoom" \notin viol

\* A pool emptied as a whole stays empty until it is credited again: no
\* extraction that ran across the clearing or the re-initialization puts
\* back credit from before it. The pool lock of esdm_pool_set_entropy() and
\* of esdm_aux_init() is what provides it.
ClearHolds == \A p \in Pools : emptied[p] => count[p] = 0

\* The XDRBG an extraction took credit from is still instantiated when it
\* is squeezed: esdm_aux_init() does not replace the context of a pool in
\* use.
ExtractSeeded ==
    \A x \in Seeders : pc[x] \in {"ex4", "ex5"} => seeded[pwm[x]]

\* A pool holds credit only for a state: there is no credit that no
\* extraction delivers, to be delivered for whatever data comes next.
CreditHasState == \A p \in Pools : count[p] > 0 => seeded[p]

\* An evaluation of the need that has returned
Returned(x) == pc[x] \in AfterLabels

\* Full pools need no more entropy: an evaluation returns the need only if
\* a pool was not full at some time while it ran, or force_fips switched
\* meanwhile.
NeedSound == \A x \in AllProcs :
    Returned(x) /\ nres[x] => ~(win[x].full /\ win[x].fips)

\* ... which the switch of force_fips cannot be left out of: read between
\* the sum and the pool size, it makes full pools look in need once.
NeedFull == \A x \in AllProcs : Returned(x) /\ nres[x] => ~win[x].full

\* The value returned is the need of some state the evaluation ran across,
\* provided neither force_fips nor the threshold changed meanwhile. It holds
\* for one pool, whose count is read once; with several pools the sum is of
\* counts read at different times, and the value may be the need
\* (NeedNotSpurious) or its absence (NeedNotMissed) of no state at all.
NeedNotSpurious == \A x \in AllProcs :
    Returned(x) /\ nres[x] =>
        win[x].ever \/ ~win[x].fips \/ ~win[x].thr
NeedNotMissed == \A x \in AllProcs :
    Returned(x) /\ ~nres[x] =>
        ~win[x].always \/ ~win[x].fips \/ ~win[x].thr

\* ... which the change of the threshold cannot be left out of, with one
\* pool either: the count is read before a threshold set after it.
NeedThrFree == \A x \in AllProcs :
    Returned(x) /\ nres[x] => win[x].ever \/ ~win[x].fips

\* The published need is the need once every operation has completed: each
\* operation that changes a count or the threshold publishes after it, the
\* evaluations for publishing are serialized, and the last of them runs
\* after every change.
NeedSettles == (\A p \in AllProcs : pc[p] = "Done") => needPub = Need

-----------------------------------------------------------------------------
(* Liveness *)

\* Every operation returns - no thread waits for a pool lock or the lock of
\* the need forever - and every process ends.
AllDone == <>(\A p \in AllProcs : pc[p] = "Done")
=============================================================================
