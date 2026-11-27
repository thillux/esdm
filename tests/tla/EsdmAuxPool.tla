----------------------------- MODULE EsdmAuxPool -----------------------------
(***************************************************************************)
(* The auxiliary entropy pool, esdm/esdm_es_aux.c, at the granularity of   *)
(* its locks and atomics: the pools with their lock and entropy count, the *)
(* writers esdm_pool_insert_aux(), esdm_pool_add_entropy(),                *)
(* esdm_pool_set_entropy(0) and esdm_aux_init(), and the seedings of the   *)
(* DRNGs that collect from it at once through esdm_aux_get_backtrack().    *)
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
(*   else.                                                                 *)
(* - The callers that trigger a seeding after an insert                    *)
(*   (esdm_es_add_entropy()) and the shared memory status are left out:    *)
(*   they run after the pool lock is dropped. The seedings are processes   *)
(*   of their own, each one esdm_get_seed_buffers() of a DRNG, which holds *)
(*   the DRNG lock or none; nothing takes a lock under a pool lock.        *)
(* - esdm_pool_set_entropy() is called with 0 only (RNDCLEARPOOL,          *)
(*   esdm_aux_reset()); esdm_aux_fini() and allocation failures are left   *)
(*   out.                                                                  *)
(* - force_fips may flip at any time where Flips > 0                       *)
(*   (esdm_config_force_fips_set()), switching the oversampling.           *)
(* - The write wakeup threshold is the variable and its readers are the    *)
(*   property NeedSound; the wakeups themselves are left out.              *)
(* - Writers and seeders run a bounded number of operations; every process *)
(*   is weakly fair.                                                       *)
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
                \* "wake" (esdm_set_write_wakeup_bits() to all pools hold)
    Credits,    \* entropy_bits of "ins" and "add", entropy units
    MaxOps,     \* operations per writer
    Seeders,    \* seedings collecting from the aux source at once
    SeedReqs,   \* their requested_bits, entropy units
    MaxSeeds,   \* collections per seeder
    XofFail,    \* the XOF may fail on an insert or an extraction
    ThreshPerIter, \* esdm_aux_get_backtrack() evaluates its threshold per
                   \* pool, as the code did before its fix
    \* the fixes, FALSE for the code before them:
    RawRoom,    \* esdm_pool_insert_aux() measures the room of a pool by the
                \* raw count
    OsrOnce,    \* esdm_aux_get_pool() reads the oversampling once
    WakeCapRead \* esdm_need_entropy() caps the threshold when it reads it

Pools == 0..NP-1
NoProc == "none"
EnvProcs == IF Flips > 0 THEN {"env"} ELSE {}
AllProcs == Writers \cup Seeders \cup EnvProcs

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
    \* ghosts: credit accepted, handed out, and lost to the cap, to a
    \* failing XOF, to clearing and to the oversampling; properties violated
    inTot = 0,
    outTot = 0,
    capLoss = 0,
    failLoss = 0,
    clearLoss = 0,
    osrLoss = 0,
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

\* esdm_pool_insert_aux() with entropy: select the pool with the most room,
\* or the first one that takes all, reading the counts unlocked; insert
\* under its lock (esdm_aux_pool_insert_locked())
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
         } else {
             failLoss := failLoss + count[sel] + ie;
             count[sel] := 0;
             seeded[sel] := FALSE;
         };
     };
     return;
}

\* esdm_pool_insert_aux() without entropy: stir every pool, stopping at the
\* first failure
procedure stir()
    variables si = 0;
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
                 si := NP;
             };
         };
     };
     return;
}

\* esdm_pool_add_entropy(): RNDADDTOENTCNT credits the first pool
procedure add(ae)
{
ad1: await lock[0] = NoProc;
     with (nc = AddCap(count[0], ae)) {
         inTot := inTot + ae;
         capLoss := capLoss + ae - (nc - count[0]);
         count[0] := nc;
     };
     return;
}

\* esdm_pool_set_entropy(0): RNDCLEARPOOL, every pool under its lock
procedure clear()
    variables ci = 0;
{
cl1: while (ci < NP) {
         await lock[ci] = NoProc;
         clearLoss := clearLoss + count[ci];
         count[ci] := 0;
         ci := ci + 1;
     };
     return;
}

\* esdm_aux_init() as the reinit callback: a new XOF context and a zero
\* count, under the pool lock
procedure reinit()
    variables ri = 0;
{
ri1: while (ri < NP) {
         await lock[ri] = NoProc;
         clearLoss := clearLoss + count[ri];
         count[ri] := 0;
         seeded[ri] := FALSE;
         ri := ri + 1;
     };
     \* esdm_set_wakeup_bits()
ri2: wakeup := MaxEnt;
     return;
}

\* esdm_aux_get_backtrack(): look the pools over, each under its lock,
\* keeping the lock of the first one that satisfies the request, else lock
\* the one with the most entropy again; extract from it
\* (esdm_aux_get_pool())
procedure extract(rq)
    variables ei = 0, maxEnt = 0, pwm = 0, held = FALSE, thr = 0,
              r = 0, o = 0, coll = 0, ret = 0;
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
         };
         coll := 0;
     };
ex6: if (lock[pwm] = self) {
         lock[pwm] := NoProc;
     } else {
         viol := viol \cup {"UnlockOwned"};
     };
     return;
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
                 \* esdm_set_write_wakeup_bits(), capped at the pool size
                 wakeup := Min(NP * Cap, MaxEnt);
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
VARIABLES count, seeded, lock, osrOn, wakeup, inTot, outTot, capLoss, 
          failLoss, clearLoss, osrLoss, viol, pc, stack

(* define statement *)
Osr == IF osrOn THEN OsrU ELSE 0

Avail(c) == Red(Min(Cap, c), Osr)

Room(c) == Cap - (IF RawRoom THEN Min(Cap, c) ELSE Avail(c))

MaxEnt == NP * Red(Cap, Osr)

VARIABLES ie, ii, maxRoom, sel, si, ae, ci, ri, rq, ei, maxEnt, pwm, held, 
          thr, r, o, coll, ret, nw, ns, nf

vars == << count, seeded, lock, osrOn, wakeup, inTot, outTot, capLoss, 
           failLoss, clearLoss, osrLoss, viol, pc, stack, ie, ii, maxRoom, 
           sel, si, ae, ci, ri, rq, ei, maxEnt, pwm, held, thr, r, o, coll, 
           ret, nw, ns, nf >>

ProcSet == (Writers) \cup (Seeders) \cup (EnvProcs)

Init == (* Global variables *)
        /\ count = [p \in Pools |-> 0]
        /\ seeded = [p \in Pools |-> TRUE]
        /\ lock = [p \in Pools |-> NoProc]
        /\ osrOn = OsrInit
        /\ wakeup = NP * Red(Cap, IF OsrInit THEN OsrU ELSE 0)
        /\ inTot = 0
        /\ outTot = 0
        /\ capLoss = 0
        /\ failLoss = 0
        /\ clearLoss = 0
        /\ osrLoss = 0
        /\ viol = {}
        (* Procedure insert *)
        /\ ie = [ self \in ProcSet |-> defaultInitValue]
        /\ ii = [ self \in ProcSet |-> 0]
        /\ maxRoom = [ self \in ProcSet |-> 0]
        /\ sel = [ self \in ProcSet |-> 0]
        (* Procedure stir *)
        /\ si = [ self \in ProcSet |-> 0]
        (* Procedure add *)
        /\ ae = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure clear *)
        /\ ci = [ self \in ProcSet |-> 0]
        (* Procedure reinit *)
        /\ ri = [ self \in ProcSet |-> 0]
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
        /\ ret = [ self \in ProcSet |-> 0]
        (* Process w *)
        /\ nw = [self \in Writers |-> 0]
        (* Process s *)
        /\ ns = [self \in Seeders |-> 0]
        (* Process en *)
        /\ nf = [self \in EnvProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Writers -> "wr0"
                                        [] self \in Seeders -> "sd0"
                                        [] self \in EnvProcs -> "en0"]

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
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, si, ae, ci, ri, rq, ei, maxEnt, pwm, 
                             held, thr, r, o, coll, ret, nw, ns, nf >>

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
                               /\ UNCHANGED failLoss
                          ELSE /\ failLoss' = failLoss + count[sel[self]] + ie[self]
                               /\ count' = [count EXCEPT ![sel[self]] = 0]
                               /\ seeded' = [seeded EXCEPT ![sel[self]] = FALSE]
                               /\ UNCHANGED << capLoss, viol >>
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ii' = [ii EXCEPT ![self] = Head(stack[self]).ii]
             /\ maxRoom' = [maxRoom EXCEPT ![self] = Head(stack[self]).maxRoom]
             /\ sel' = [sel EXCEPT ![self] = Head(stack[self]).sel]
             /\ ie' = [ie EXCEPT ![self] = Head(stack[self]).ie]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << lock, osrOn, wakeup, outTot, clearLoss, osrLoss, 
                             si, ae, ci, ri, rq, ei, maxEnt, pwm, held, thr, r, 
                             o, coll, ret, nw, ns, nf >>

insert(self) == is1(self) \/ is2(self)

st1(self) == /\ pc[self] = "st1"
             /\ IF si[self] < NP
                   THEN /\ lock[si[self]] = NoProc
                        /\ \E ok \in XofOK:
                             IF ok
                                THEN /\ seeded' = [seeded EXCEPT ![si[self]] = TRUE]
                                     /\ si' = [si EXCEPT ![self] = si[self] + 1]
                                     /\ UNCHANGED << count, failLoss >>
                                ELSE /\ failLoss' = failLoss + count[si[self]]
                                     /\ count' = [count EXCEPT ![si[self]] = 0]
                                     /\ seeded' = [seeded EXCEPT ![si[self]] = FALSE]
                                     /\ si' = [si EXCEPT ![self] = NP]
                        /\ pc' = [pc EXCEPT ![self] = "st1"]
                        /\ stack' = stack
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ si' = [si EXCEPT ![self] = Head(stack[self]).si]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << count, seeded, failLoss >>
             /\ UNCHANGED << lock, osrOn, wakeup, inTot, outTot, capLoss, 
                             clearLoss, osrLoss, viol, ie, ii, maxRoom, sel, 
                             ae, ci, ri, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             coll, ret, nw, ns, nf >>

stir(self) == st1(self)

ad1(self) == /\ pc[self] = "ad1"
             /\ lock[0] = NoProc
             /\ LET nc == AddCap(count[0], ae[self]) IN
                  /\ inTot' = inTot + ae[self]
                  /\ capLoss' = capLoss + ae[self] - (nc - count[0])
                  /\ count' = [count EXCEPT ![0] = nc]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ae' = [ae EXCEPT ![self] = Head(stack[self]).ae]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, outTot, failLoss, 
                             clearLoss, osrLoss, viol, ie, ii, maxRoom, sel, 
                             si, ci, ri, rq, ei, maxEnt, pwm, held, thr, r, o, 
                             coll, ret, nw, ns, nf >>

add(self) == ad1(self)

cl1(self) == /\ pc[self] = "cl1"
             /\ IF ci[self] < NP
                   THEN /\ lock[ci[self]] = NoProc
                        /\ clearLoss' = clearLoss + count[ci[self]]
                        /\ count' = [count EXCEPT ![ci[self]] = 0]
                        /\ ci' = [ci EXCEPT ![self] = ci[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "cl1"]
                        /\ stack' = stack
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ ci' = [ci EXCEPT ![self] = Head(stack[self]).ci]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << count, clearLoss >>
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, osrLoss, viol, ie, ii, maxRoom, 
                             sel, si, ae, ri, rq, ei, maxEnt, pwm, held, thr, 
                             r, o, coll, ret, nw, ns, nf >>

clear(self) == cl1(self)

ri1(self) == /\ pc[self] = "ri1"
             /\ IF ri[self] < NP
                   THEN /\ lock[ri[self]] = NoProc
                        /\ clearLoss' = clearLoss + count[ri[self]]
                        /\ count' = [count EXCEPT ![ri[self]] = 0]
                        /\ seeded' = [seeded EXCEPT ![ri[self]] = FALSE]
                        /\ ri' = [ri EXCEPT ![self] = ri[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "ri1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ri2"]
                        /\ UNCHANGED << count, seeded, clearLoss, ri >>
             /\ UNCHANGED << lock, osrOn, wakeup, inTot, outTot, capLoss, 
                             failLoss, osrLoss, viol, stack, ie, ii, maxRoom, 
                             sel, si, ae, ci, rq, ei, maxEnt, pwm, held, thr, 
                             r, o, coll, ret, nw, ns, nf >>

ri2(self) == /\ pc[self] = "ri2"
             /\ wakeup' = MaxEnt
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ri' = [ri EXCEPT ![self] = Head(stack[self]).ri]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, lock, osrOn, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, ie, 
                             ii, maxRoom, sel, si, ae, ci, rq, ei, maxEnt, pwm, 
                             held, thr, r, o, coll, ret, nw, ns, nf >>

reinit(self) == ri1(self) \/ ri2(self)

ex0(self) == /\ pc[self] = "ex0"
             /\ thr' = [thr EXCEPT ![self] = rq[self] + Osr]
             /\ pc' = [pc EXCEPT ![self] = "ex1"]
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             ei, maxEnt, pwm, held, r, o, coll, ret, nw, ns, 
                             nf >>

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
             /\ UNCHANGED << count, seeded, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             thr, r, o, coll, ret, nw, ns, nf >>

ex2(self) == /\ pc[self] = "ex2"
             /\ IF ~held[self]
                   THEN /\ lock[pwm[self]] = NoProc
                        /\ lock' = [lock EXCEPT ![pwm[self]] = self]
                   ELSE /\ TRUE
                        /\ lock' = lock
             /\ pc' = [pc EXCEPT ![self] = "ex3"]
             /\ UNCHANGED << count, seeded, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, coll, ret, nw, 
                             ns, nf >>

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
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, stack, ie, 
                             ii, maxRoom, sel, si, ae, ci, ri, rq, ei, maxEnt, 
                             pwm, held, thr, ret, nw, ns, nf >>

ex4(self) == /\ pc[self] = "ex4"
             /\ IF coll[self] > r[self] + o[self]
                   THEN /\ count' = [count EXCEPT ![pwm[self]] = count[pwm[self]] + coll[self] - (r[self] + o[self])]
                        /\ coll' = [coll EXCEPT ![self] = r[self] + o[self]]
                   ELSE /\ TRUE
                        /\ UNCHANGED << count, coll >>
             /\ pc' = [pc EXCEPT ![self] = "ex5"]
             /\ UNCHANGED << seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, ret, nw, ns, nf >>

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
                               /\ UNCHANGED << count, seeded, failLoss >>
                          ELSE /\ failLoss' = failLoss + count[pwm[self]] + coll[self]
                               /\ count' = [count EXCEPT ![pwm[self]] = 0]
                               /\ seeded' = [seeded EXCEPT ![pwm[self]] = FALSE]
                               /\ UNCHANGED << outTot, osrLoss, viol >>
                    /\ coll' = [coll EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "ex6"]
             /\ UNCHANGED << lock, osrOn, wakeup, inTot, capLoss, clearLoss, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, ret, nw, ns, nf >>

ex6(self) == /\ pc[self] = "ex6"
             /\ IF lock[pwm[self]] = self
                   THEN /\ lock' = [lock EXCEPT ![pwm[self]] = NoProc]
                        /\ viol' = viol
                   ELSE /\ viol' = (viol \cup {"UnlockOwned"})
                        /\ lock' = lock
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ ei' = [ei EXCEPT ![self] = Head(stack[self]).ei]
             /\ maxEnt' = [maxEnt EXCEPT ![self] = Head(stack[self]).maxEnt]
             /\ pwm' = [pwm EXCEPT ![self] = Head(stack[self]).pwm]
             /\ held' = [held EXCEPT ![self] = Head(stack[self]).held]
             /\ thr' = [thr EXCEPT ![self] = Head(stack[self]).thr]
             /\ r' = [r EXCEPT ![self] = Head(stack[self]).r]
             /\ o' = [o EXCEPT ![self] = Head(stack[self]).o]
             /\ coll' = [coll EXCEPT ![self] = Head(stack[self]).coll]
             /\ ret' = [ret EXCEPT ![self] = Head(stack[self]).ret]
             /\ rq' = [rq EXCEPT ![self] = Head(stack[self]).rq]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << count, seeded, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, ie, ii, 
                             maxRoom, sel, si, ae, ci, ri, nw, ns, nf >>

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
                                     /\ UNCHANGED << wakeup, si, ae, ci, ri >>
                                ELSE /\ IF op = "stir"
                                           THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "stir",
                                                                                         pc        |->  "wr0",
                                                                                         si        |->  si[self] ] >>
                                                                                     \o stack[self]]
                                                /\ si' = [si EXCEPT ![self] = 0]
                                                /\ pc' = [pc EXCEPT ![self] = "st1"]
                                                /\ UNCHANGED << wakeup, ae, ci, 
                                                                ri >>
                                           ELSE /\ IF op = "add"
                                                      THEN /\ \E cr \in Credits:
                                                                /\ /\ ae' = [ae EXCEPT ![self] = cr]
                                                                   /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "add",
                                                                                                            pc        |->  "wr0",
                                                                                                            ae        |->  ae[self] ] >>
                                                                                                        \o stack[self]]
                                                                /\ pc' = [pc EXCEPT ![self] = "ad1"]
                                                           /\ UNCHANGED << wakeup, 
                                                                           ci, 
                                                                           ri >>
                                                      ELSE /\ IF op = "clear"
                                                                 THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "clear",
                                                                                                               pc        |->  "wr0",
                                                                                                               ci        |->  ci[self] ] >>
                                                                                                           \o stack[self]]
                                                                      /\ ci' = [ci EXCEPT ![self] = 0]
                                                                      /\ pc' = [pc EXCEPT ![self] = "cl1"]
                                                                      /\ UNCHANGED << wakeup, 
                                                                                      ri >>
                                                                 ELSE /\ IF op = "wake"
                                                                            THEN /\ wakeup' = Min(NP * Cap, MaxEnt)
                                                                                 /\ pc' = [pc EXCEPT ![self] = "wr0"]
                                                                                 /\ UNCHANGED << stack, 
                                                                                                 ri >>
                                                                            ELSE /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "reinit",
                                                                                                                          pc        |->  "wr0",
                                                                                                                          ri        |->  ri[self] ] >>
                                                                                                                      \o stack[self]]
                                                                                 /\ ri' = [ri EXCEPT ![self] = 0]
                                                                                 /\ pc' = [pc EXCEPT ![self] = "ri1"]
                                                                                 /\ UNCHANGED wakeup
                                                                      /\ ci' = ci
                                                           /\ ae' = ae
                                                /\ si' = si
                                     /\ UNCHANGED << ie, ii, maxRoom, sel >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << wakeup, stack, ie, ii, maxRoom, sel, 
                                        si, ae, ci, ri, nw >>
             /\ UNCHANGED << count, seeded, lock, osrOn, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, coll, ret, ns, 
                             nf >>

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
                                                                         ret       |->  ret[self],
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
                             /\ ret' = [ret EXCEPT ![self] = 0]
                             /\ pc' = [pc EXCEPT ![self] = "ex0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, rq, ei, maxEnt, pwm, held, thr, 
                                        r, o, coll, ret, ns >>
             /\ UNCHANGED << count, seeded, lock, osrOn, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, ie, 
                             ii, maxRoom, sel, si, ae, ci, ri, nw, nf >>

s(self) == sd0(self)

en0(self) == /\ pc[self] = "en0"
             /\ IF nf[self] < Flips
                   THEN /\ nf' = [nf EXCEPT ![self] = nf[self] + 1]
                        /\ osrOn' = ~osrOn
                        /\ pc' = [pc EXCEPT ![self] = "en0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << osrOn, nf >>
             /\ UNCHANGED << count, seeded, lock, wakeup, inTot, outTot, 
                             capLoss, failLoss, clearLoss, osrLoss, viol, 
                             stack, ie, ii, maxRoom, sel, si, ae, ci, ri, rq, 
                             ei, maxEnt, pwm, held, thr, r, o, coll, ret, nw, 
                             ns >>

en(self) == en0(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in ProcSet:  \/ insert(self) \/ stir(self) \/ add(self)
                               \/ clear(self) \/ reinit(self)
                               \/ extract(self))
           \/ (\E self \in Writers: w(self))
           \/ (\E self \in Seeders: s(self))
           \/ (\E self \in EnvProcs: en(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Writers : /\ WF_vars(w(self))
                                 /\ WF_vars(insert(self))
                                 /\ WF_vars(stir(self))
                                 /\ WF_vars(add(self))
                                 /\ WF_vars(clear(self))
                                 /\ WF_vars(reinit(self))
        /\ \A self \in Seeders : WF_vars(s(self)) /\ WF_vars(extract(self))
        /\ \A self \in EnvProcs : WF_vars(en(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ count \in [Pools -> 0..Cap]
    /\ seeded \in [Pools -> BOOLEAN]
    /\ lock \in [Pools -> AllProcs \cup {NoProc}]
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

\* esdm_need_entropy(): writers of /dev/random are woken
Need == SumF([p \in Pools |-> Avail(count[p])], Pools)
            < (IF WakeCapRead THEN Min(wakeup, MaxEnt) ELSE wakeup)

\* Pools that are full need no more entropy: the write wakeup threshold
\* stays within what they hold.
NeedSound == (\A p \in Pools : count[p] = Cap) => ~Need

\* The count never exceeds the capacity of a pool.
CountBound == \A p \in Pools : count[p] <= Cap

\* A process holds at most one pool lock: there is no lock order to keep.
OneLock == \A p \in AllProcs : Cardinality({q \in Pools : lock[q] = p}) <= 1

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

-----------------------------------------------------------------------------
(* Liveness *)

AllDone == <>(\A p \in AllProcs : pc[p] = "Done")
=============================================================================
