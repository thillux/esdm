--------------------------- MODULE EsdmSupervisor ---------------------------
(***************************************************************************)
(* The PID namespace supervisor: linux_isolate_namespace_prefork() of      *)
(* common/linux_support.c with its callers frontends/server/server_main.c  *)
(* (--pid_namespace, supervisor_exit()) and frontends/cuse/cuse_device.c.  *)
(* One step is one system call or one access to linux_pidns_child; the pc  *)
(* values name the C calls they come from.                                 *)
(*                                                                         *)
(* Signals are asynchronous. Each process has a mask, a pending set and a  *)
(* disposition per signal. A pending signal that is not blocked is         *)
(* delivered before the process takes its next step, also out of a         *)
(* blocking waitpid(), which SA_RESTART resumes. A handler runs as a frame *)
(* on top of the interrupted code with its signal blocked; the forwarder's *)
(* sa_mask is empty, so other signals nest. fork() passes the mask and the *)
(* dispositions on, not the pending signals. The daemon is the init of the *)
(* new namespace: a signal it has no handler for is discarded when sent    *)
(* from the supervisor's namespace, unless blocked, and again when         *)
(* delivered (SIGNAL_UNKILLABLE), so it dies only by SIGKILL or a fault.   *)
(* With SIGCHLD ignored the kernel reaps the daemon itself and waitpid()   *)
(* fails with ECHILD. A reaped PID may be handed out again.                *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - "TERM" stands for SIGHUP, SIGINT, SIGQUIT and SIGTERM, which both     *)
(*   frontends handle and the supervisor forwards; "USR1" for SIGUSR1,     *)
(*   forwarded, the server's suspend trigger and a CUSE termination        *)
(*   signal; "USR2" for the CUSE termination signals not forwarded         *)
(*   (SIGALRM, SIGIO, SIGPROF, SIGPWR, SIGUSR2, SIGVTALRM, SIGXCPU,        *)
(*   SIGXFSZ), which the server does not handle. "SEGV" is a fault, "KILL" *)
(*   SIGKILL.                                                              *)
(* - The daemon is one process with the steps that matter for signals: the *)
(*   child's sigprocmask() in the prefork, its sigaction()s after it       *)
(*   (server: esdm_shm_status_install_signal_suspend(), CUSE:              *)
(*   esdm_cuse_install_sig_handler()), for CUSE the session setup that sets*)
(*   esdm_cuse_session, then serving. A termination handler makes it exit  *)
(*   with 0: the server's latches server_exit at any time, the CUSE one    *)
(*   acts only once the session exists (Latch). The daemon may also exit   *)
(*   with 1, fault or be killed by SIGKILL at any time.                    *)
(* - A handler's kill() and its return are one step.                       *)
(* - The caller's signal mask is empty; no disposition is SIG_IGN but      *)
(*   SIGCHLD's (ChldIgn).                                                  *)
(* - Not modelled: unshare() and fork() failing, PR_SET_PDEATHSIG (best    *)
(*   effort, cleared by the privilege drop), stop signals, the threads of  *)
(*   the daemon, signals sent to the daemon directly, and the supervisor   *)
(*   dying by SIGKILL.                                                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Sigs,         \* catchable signals sent: "TERM", "USR1", "USR2"
    Fwd,          \* fwd_signals[], the signals the supervisor forwards
    PreHandlers,  \* handlers the caller installs before the prefork
    PostHandlers, \* handlers the daemon installs after it
    TermSigs,     \* handlers that make the daemon terminate
    Latch,        \* a termination handler acts before the daemon serves
    Callback,     \* supervisor_exit_cb is set
    SendSigs,     \* signals others send to the supervisor
    MaxSends,     \* how many
    Fates,        \* how the daemon may end on its own: "exit1", "SEGV", "KILL"
    Checked,      \* signals that must reach the daemon's handler
    ChldIgn,      \* SIGCHLD is inherited as SIG_IGN
    Unblocked,    \* the code before 9a53de9d: Fwd not blocked across fork()
    FixChld,      \* fix: SIGCHLD to SIG_DFL across fork()
    FixReap       \* fix: waitid(WNOWAIT), block Fwd, clear the PID, reap

SDom == Sigs \cup {"SEGV"}
Faults == {"SEGV", "KILL"}
DaemonSet == PreHandlers \cup PostHandlers
SPcs == {"sigprocmask_block", "sigaction_chld", "fork", "store_child",
         "sigaction", "sigprocmask_setmask", "waitid", "sigprocmask_block2",
         "clear_child", "waitpid", "supervisor_exit_cb", "signal", "raise",
         "exit_128", "exit", "exit_failure"}

VARIABLES
    \* supervisor
    spc,      \* main code
    sstack,   \* handler frames, the innermost last
    slife,    \* "alive", "dead"
    smask,
    spend,
    sdisp,    \* "DFL", "caller" (inherited daemon handler), "fwd"
    schld,    \* SIGCHLD disposition
    sflag,    \* server_exit set by a caller's handler in the supervisor
    todo,     \* forwarders left to install
    child,    \* linux_pidns_child: 0, or 1 naming the daemon
    wst,      \* the status waitpid() returned
    raised,   \* the signal raise() sent
    how,      \* how the supervisor ended: "exit", "raise", "signal"
    sfinal,   \* its exit status or signal
    cbRuns,   \* supervisor_exit_cb() calls
    \* daemon
    clife,    \* "unborn", "alive", "zombie", "reaped"
    cpc,
    cmask,
    cpend,
    chand,    \* signals with a handler
    cstop,    \* a termination handler ran
    cstatus,
    \* environment
    sent,
    reused,   \* the daemon's PID is another process's now
    \* ghosts: signals owed to the daemon, a termination signal sent,
    \* properties violated
    owed,
    stopReq,
    viol

sv == <<spc, sstack, slife, smask, spend, sdisp, schld, sflag, todo, child,
        wst, raised, how, sfinal, cbRuns>>
cv == <<clife, cpc, cmask, cpend, chand, cstop, cstatus>>
vars == <<sv, cv, sent, reused, owed, stopReq, viol>>

Init ==
    /\ spc = "sigprocmask_block"
    /\ sstack = <<>>
    /\ slife = "alive"
    /\ smask = {}
    /\ spend = {}
    /\ sdisp = [s \in SDom |-> IF s \in PreHandlers THEN "caller" ELSE "DFL"]
    /\ schld = IF ChldIgn THEN "IGN" ELSE "DFL"
    /\ sflag = FALSE
    /\ todo = Fwd
    /\ child = 0
    /\ wst = "none"
    /\ raised = "none"
    /\ how = "none"
    /\ sfinal = "none"
    /\ cbRuns = 0
    /\ clife = "unborn"
    /\ cpc = "none"
    /\ cmask = {}
    /\ cpend = {}
    /\ chand = {}
    /\ cstop = FALSE
    /\ cstatus = "none"
    /\ sent = 0
    /\ reused = FALSE
    /\ owed = {}
    /\ stopReq = FALSE
    /\ viol = {}

-----------------------------------------------------------------------------
(* Helpers *)

\* A signal owed to the daemon is gone without reaching its handler
Lose(s) == /\ viol' = IF s \in owed THEN viol \cup {"Lost"} ELSE viol
           /\ owed' = owed \ {s}

\* kill(pid, s) by the supervisor, pid naming the daemon
Kill(s) ==
    IF clife = "alive"
    THEN IF s \in cmask \/ s \in chand
         THEN /\ cpend' = cpend \cup {s}
              /\ UNCHANGED <<owed, viol>>
         ELSE /\ Lose(s)        \* no handler at a namespace init
              /\ UNCHANGED cpend
    ELSE /\ viol' = IF clife = "reaped"
                    THEN viol \cup {"KillAfterReap"}
                         \cup (IF reused THEN {"KillRecycled"} ELSE {})
                    ELSE viol   \* a zombie: no effect
         /\ UNCHANGED <<cpend, owed>>

AfterCb(st) == IF st \in Faults THEN "signal" ELSE "exit"

\* The supervisor's main code runs: no handler active, nothing to deliver
SMainOK == slife = "alive" /\ sstack = <<>> /\ spend \ smask = {}

SExit(st) ==
    /\ SMainOK
    /\ slife' = "dead"
    /\ how' = "exit"
    /\ sfinal' = st
    /\ UNCHANGED <<spc, sstack, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

-----------------------------------------------------------------------------
(* Supervisor: linux_isolate_namespace_prefork() from its first sigprocmask *)

\* linux_support.c:99 sigprocmask(SIG_BLOCK, &fwd_set, &old_set)
SBlock ==
    /\ SMainOK /\ spc = "sigprocmask_block"
    /\ smask' = IF Unblocked THEN smask ELSE smask \cup Fwd
    /\ spc' = IF FixChld THEN "sigaction_chld" ELSE "fork"
    /\ UNCHANGED <<sstack, slife, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fix: sigaction(SIGCHLD, SIG_DFL), restored in the child
SChld ==
    /\ SMainOK /\ spc = "sigaction_chld"
    /\ schld' = "DFL"
    /\ spc' = "fork"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :101 fork(): the child is PID 1 of the namespace, with the supervisor's
\* mask and handlers and none of its pending signals
SFork ==
    /\ SMainOK /\ spc = "fork"
    /\ spc' = "store_child"
    /\ clife' = "alive"
    /\ cpc' = "sigprocmask"
    /\ cmask' = smask
    /\ cpend' = {}
    /\ chand' = {s \in Sigs : sdisp[s] = "caller"}
    /\ cstop' = sflag
    /\ UNCHANGED cstatus
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<sent, reused, owed, stopReq, viol>>

\* :137 linux_pidns_child = pid
SStore ==
    /\ SMainOK /\ spc = "store_child"
    /\ child' = 1
    /\ spc' = "sigaction"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :147-148 sigaction(fwd_signals[i], linux_pidns_forward_signal), each
SSigaction ==
    /\ SMainOK /\ spc = "sigaction"
    /\ LET s == CHOOSE x \in todo : TRUE IN
       /\ sdisp' = [sdisp EXCEPT ![s] = "fwd"]
       /\ todo' = todo \ {s}
       /\ spc' = IF todo = {s} THEN "sigprocmask_setmask" ELSE "sigaction"
    /\ UNCHANGED <<sstack, slife, smask, spend, schld, sflag, child, wst,
                   raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :149 sigprocmask(SIG_SETMASK, &old_set, NULL)
SSetmask ==
    /\ SMainOK /\ spc = "sigprocmask_setmask"
    /\ smask' = {}
    /\ spc' = IF FixReap THEN "waitid" ELSE "waitpid"
    /\ UNCHANGED <<sstack, slife, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fix: waitid(P_PID, pid, &info, WEXITED | WNOWAIT) - the daemon stays a
\* zombie; ECHILD if the kernel reaped it
SWaitid ==
    /\ SMainOK /\ spc = "waitid"
    /\ clife \in {"zombie", "reaped"}
    /\ spc' = IF clife = "zombie" THEN "sigprocmask_block2" ELSE "exit_failure"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fix: sigprocmask(SIG_BLOCK, &fwd_set, NULL)
SBlock2 ==
    /\ SMainOK /\ spc = "sigprocmask_block2"
    /\ smask' = smask \cup Fwd
    /\ spc' = "clear_child"
    /\ UNCHANGED <<sstack, slife, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fix: linux_pidns_child = 0
SClear ==
    /\ SMainOK /\ spc = "clear_child"
    /\ child' = 0
    /\ spc' = "waitpid"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :151-160 waitpid(pid, &status, 0) reaps the daemon; ECHILD if the kernel
\* did, then exit(EXIT_FAILURE)
SWaitpid ==
    /\ SMainOK /\ spc = "waitpid"
    /\ clife \in {"zombie", "reaped"}
    /\ IF clife = "zombie"
       THEN /\ clife' = "reaped"
            /\ wst' = cstatus
            /\ spc' = IF Callback THEN "supervisor_exit_cb"
                      ELSE AfterCb(cstatus)
       ELSE /\ spc' = "exit_failure"
            /\ UNCHANGED <<clife, wst>>
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cpc, cmask, cpend, chand, cstop, cstatus>>
    /\ UNCHANGED <<sent, reused, owed, stopReq, viol>>

\* :167-168 supervisor_exit_cb(): supervisor_exit(), esdm_rpc_server_cleanup()
SCallback ==
    /\ SMainOK /\ spc = "supervisor_exit_cb"
    /\ cbRuns' = cbRuns + 1
    /\ viol' = IF clife \in {"zombie", "reaped"} THEN viol
               ELSE viol \cup {"CleanupEarly"}
    /\ spc' = AfterCb(wst)
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq>>

\* :178 signal(sig, SIG_DFL), which fails for SIGKILL
SSignal ==
    /\ SMainOK /\ spc = "signal"
    /\ sdisp' = IF wst \in SDom THEN [sdisp EXCEPT ![wst] = "DFL"] ELSE sdisp
    /\ spc' = "raise"
    /\ UNCHANGED <<sstack, slife, smask, spend, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :179 raise(sig)
SRaise ==
    /\ SMainOK /\ spc = "raise"
    /\ raised' = wst
    /\ IF wst = "KILL"
       THEN /\ slife' = "dead"
            /\ how' = "raise"
            /\ sfinal' = "KILL"
            /\ UNCHANGED <<spc, spend>>
       ELSE /\ spend' = spend \cup {wst}
            /\ spc' = "exit_128"
            /\ UNCHANGED <<slife, how, sfinal>>
    /\ UNCHANGED <<sstack, smask, sdisp, schld, sflag, todo, child, wst,
                   cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :181 exit(128 + sig), :184 exit(WEXITSTATUS(status)), :158 exit(EXIT_FAILURE)
SExit128 == spc = "exit_128" /\ SExit("exit128")
SExitStatus == spc = "exit" /\ SExit(wst)
SExitFailure == spc = "exit_failure" /\ SExit("exit1")

\* The kernel delivers a pending signal that is not blocked
SDeliver ==
    /\ slife = "alive"
    /\ \E s \in spend \ smask :
        /\ spend' = spend \ {s}
        /\ CASE sdisp[s] = "fwd" ->
                  /\ sstack' = Append(sstack, [pc |-> "fwd_load", sig |-> s,
                                               ch |-> 0, om |-> smask])
                  /\ smask' = smask \cup {s}
                  /\ UNCHANGED <<slife, how, sfinal, sflag, owed, viol>>
             [] sdisp[s] = "caller" ->
                  \* the daemon's handler, run in the supervisor: before
                  \* fork() the server's flag passes to the daemon
                  /\ IF Latch /\ s \in TermSigs /\ clife = "unborn"
                     THEN /\ sflag' = TRUE
                          /\ owed' = owed \ {s}
                          /\ UNCHANGED viol
                     ELSE /\ Lose(s)
                          /\ UNCHANGED sflag
                  /\ UNCHANGED <<sstack, smask, slife, how, sfinal>>
             [] OTHER ->
                  \* SIG_DFL terminates
                  /\ slife' = "dead"
                  /\ how' = IF s = raised THEN "raise" ELSE "signal"
                  /\ sfinal' = s
                  /\ viol' = viol
                        \cup (IF s \in owed THEN {"Lost"} ELSE {})
                        \cup (IF s # raised /\ clife \in {"alive", "zombie"}
                              THEN {"Orphan"} \cup
                                   (IF s \in DaemonSet
                                    THEN {"UnforwardedKill"} ELSE {})
                              ELSE {})
                  /\ owed' = owed \ {s}
                  /\ UNCHANGED <<sstack, smask, sflag>>
    /\ UNCHANGED <<spc, sdisp, schld, todo, child, wst, raised, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, stopReq>>

Top == sstack[Len(sstack)]

\* :48 linux_pidns_forward_signal(): child = linux_pidns_child
SFwdLoad ==
    /\ slife = "alive" /\ sstack # <<>> /\ spend \ smask = {}
    /\ Top.pc = "fwd_load"
    /\ sstack' = [sstack EXCEPT ![Len(sstack)] =
                      [Top EXCEPT !.pc = "fwd_kill", !.ch = child]]
    /\ UNCHANGED <<spc, slife, smask, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* :50-51 if (child > 0) kill(child, sig), and the handler's return
SFwdKill ==
    /\ slife = "alive" /\ sstack # <<>> /\ spend \ smask = {}
    /\ Top.pc = "fwd_kill"
    /\ sstack' = SubSeq(sstack, 1, Len(sstack) - 1)
    /\ smask' = Top.om
    /\ IF Top.ch # 0 THEN Kill(Top.sig)
       ELSE IF clife \in {"unborn", "alive"}
            THEN Lose(Top.sig) /\ UNCHANGED cpend
            ELSE UNCHANGED <<cpend, owed, viol>>
    /\ UNCHANGED <<spc, slife, spend, sdisp, schld, sflag, todo, child, wst,
                   raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstop, cstatus>>
    /\ UNCHANGED <<sent, reused, stopReq>>

SNext ==
    \/ SDeliver \/ SFwdLoad \/ SFwdKill
    \/ SBlock \/ SChld \/ SFork \/ SStore \/ SSigaction \/ SSetmask
    \/ SWaitid \/ SBlock2 \/ SClear \/ SWaitpid \/ SCallback \/ SSignal
    \/ SRaise \/ SExit128 \/ SExitStatus \/ SExitFailure

-----------------------------------------------------------------------------
(* Daemon *)

CReady == clife = "alive" /\ cpend \ cmask = {}

\* The daemon ends; with SIGCHLD ignored the kernel reaps it at once
CExit(st) ==
    /\ clife' = IF schld = "IGN" /\ slife = "alive" THEN "reaped" ELSE "zombie"
    /\ cstatus' = st
    /\ owed' = {}
    /\ UNCHANGED <<cpc, cmask, cpend, chand, cstop>>
    /\ UNCHANGED <<sv, sent, reused, stopReq, viol>>

\* The kernel delivers a pending signal: to a handler, else it is discarded
\* (namespace init)
CDeliver ==
    /\ clife = "alive"
    /\ \E s \in cpend \ cmask :
        /\ cpend' = cpend \ {s}
        /\ IF s \in chand /\ (Latch \/ cpc = "serve" \/ s \notin TermSigs)
           THEN /\ cstop' = (cstop \/ s \in TermSigs)
                /\ owed' = owed \ {s}
                /\ UNCHANGED viol
           ELSE \* SIG_DFL, or esdm_cuse_sig_handler() without a session
                /\ Lose(s)
                /\ UNCHANGED cstop
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstatus>>
    /\ UNCHANGED <<sv, sent, reused, stopReq>>

\* :112 the child's sigprocmask(SIG_SETMASK, &old_set, NULL), :121 prctl()
CUnmask ==
    /\ CReady /\ cpc = "sigprocmask"
    /\ cmask' = {}
    /\ cpc' = "sigaction"
    /\ UNCHANGED <<clife, cpend, chand, cstop, cstatus>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* the daemon's sigaction()s after the prefork
CSigaction ==
    /\ CReady /\ cpc = "sigaction"
    /\ chand' = chand \cup PostHandlers
    /\ cpc' = IF Latch THEN "serve" ELSE "cuse_lowlevel_setup"
    /\ UNCHANGED <<clife, cmask, cpend, cstop, cstatus>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* esdm_cuse_session = cuse_lowlevel_setup()
CSetup ==
    /\ CReady /\ cpc = "cuse_lowlevel_setup"
    /\ cpc' = "serve"
    /\ UNCHANGED <<clife, cmask, cpend, chand, cstop, cstatus>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* a termination handler ran: the daemon tears down and returns 0
CStopExit == CReady /\ cstop /\ CExit("exit0")

\* it fails, faults or is killed by SIGKILL
CFate == clife = "alive" /\ \E f \in Fates : CExit(f)

CNext == CDeliver \/ CUnmask \/ CSigaction \/ CSetup \/ CStopExit

-----------------------------------------------------------------------------
(* Environment *)

\* kill(supervisor, s) by systemd, esdm-server-signal-helper or anybody;
\* owed to the daemon once the prefork began and while it may live
ESend ==
    /\ slife = "alive" /\ sent < MaxSends
    /\ \E s \in SendSigs :
        LET arm == spc # "sigprocmask_block" /\ clife \in {"unborn", "alive"}
        IN /\ spend' = spend \cup {s}
           /\ owed' = IF arm /\ s \in Checked THEN owed \cup {s} ELSE owed
           /\ stopReq' = (stopReq \/ (arm /\ s \in TermSigs))
    /\ sent' = sent + 1
    /\ UNCHANGED <<spc, sstack, slife, smask, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, reused, viol>>

\* the reaped PID goes to a new process
EReuse ==
    /\ clife = "reaped" /\ ~reused
    /\ reused' = TRUE
    /\ UNCHANGED <<sv, cv, sent, owed, stopReq, viol>>

\* Nothing left to do: the supervisor ended, or it waits for a daemon that
\* serves
Final ==
    \/ slife = "dead"
    \/ /\ spc \in {"waitpid", "waitid"} /\ sstack = <<>>
       /\ spend \ smask = {}
       /\ clife = "alive" /\ cpc = "serve" /\ ~cstop /\ cpend \ cmask = {}

Done == Final /\ UNCHANGED vars

Next == SNext \/ CNext \/ CFate \/ ESend \/ EReuse \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(SNext) /\ WF_vars(CNext)

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ spc \in SPcs
    /\ slife \in {"alive", "dead"}
    /\ smask \subseteq SDom /\ spend \subseteq SDom
    /\ sdisp \in [SDom -> {"DFL", "caller", "fwd"}]
    /\ child \in {0, 1}
    /\ Len(sstack) <= Cardinality(SDom)
    /\ clife \in {"unborn", "alive", "zombie", "reaped"}
    /\ cmask \subseteq Sigs /\ cpend \subseteq Sigs /\ chand \subseteq Sigs
    /\ owed \subseteq Checked

\* A signal of Checked sent to the supervisor once the prefork began
\* reaches the daemon's handler unless the daemon ends first: no handler
\* of the supervisor takes it, the supervisor does not die by it, the
\* kernel does not discard it at the namespace init.
NoLostSignal == "Lost" \notin viol

\* No kill() goes to the daemon's PID after it was reaped ...
NoKillAfterReap == "KillAfterReap" \notin viol

\* ... and none reaches the process the PID went to next.
NoKillRecycled == "KillRecycled" \notin viol

\* Ending by its own exit() or raise(), the supervisor ends as the daemon
\* did: with its exit status, or by its signal.
ExitMirrors == (slife = "dead" /\ how \in {"exit", "raise"}) => sfinal = cstatus

\* The callback runs at most once, only after the daemon ended, and on every
\* way out the supervisor takes itself.
CleanupOnce ==
    /\ cbRuns <= 1
    /\ "CleanupEarly" \notin viol
    /\ (Callback /\ slife = "dead" /\ how \in {"exit", "raise"}) => cbRuns = 1

\* No signal the daemon handles kills the supervisor before it reaped the
\* daemon ...
NoUnforwardedKill == "UnforwardedKill" \notin viol

\* ... nor does any other signal.
NoOrphan == "Orphan" \notin viol

-----------------------------------------------------------------------------
(* Liveness *)

\* The supervisor ends once the daemon did.
SupervisorExits ==
    (slife = "alive" /\ clife \in {"zombie", "reaped"}) ~> (slife = "dead")

\* A signal owed to the daemon reaches it or the daemon ends.
OwedReaches == \A s \in Checked : (s \in owed) ~> (s \notin owed)

\* A termination signal sent to the supervisor ends both.
StopEndsBoth ==
    stopReq ~> (slife = "dead" /\ clife \in {"zombie", "reaped"})

=============================================================================
