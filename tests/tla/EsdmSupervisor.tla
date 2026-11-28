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
(* blocking waitid() or waitpid(), which SA_RESTART resumes. A handler     *)
(* runs as a frame on top of the interrupted code with its signal and its  *)
(* sa_mask blocked; the forwarder's sa_mask is the forwarded set, so no    *)
(* forwarder nests in another. fork() passes the mask and the dispositions *)
(* on, not the pending signals. The daemon is the init of the new          *)
(* namespace: a signal it has no handler for is discarded when sent from   *)
(* the supervisor's namespace, unless blocked, and again when delivered    *)
(* (SIGNAL_UNKILLABLE), so it dies only by SIGKILL or a fault. With        *)
(* SIGCHLD ignored the kernel reaps the daemon itself and waitid() and     *)
(* waitpid() fail with ECHILD. A reaped PID may be handed out again.       *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - "TERM" stands for SIGHUP, SIGINT, SIGQUIT and SIGTERM, which both     *)
(*   frontends handle; "USR1" for SIGUSR1, the server's suspend trigger    *)
(*   and a CUSE termination signal; "USR2" for the other signals of        *)
(*   linux_term_signals() (SIGALRM, SIGIO, SIGPROF, SIGPWR, SIGUSR2,       *)
(*   SIGVTALRM, SIGXCPU, SIGXFSZ, SIGSTKFLT, the real-time signals), which *)
(*   end a CUSE daemon and which the server does not handle; "ABRT" for    *)
(*   linux_pidns_sent_signals[], the remaining signals a handler can catch *)
(*   and a process ends by, sent with kill(): SIGABRT, SIGPIPE and the     *)
(*   fault signals, which no daemon handles. The supervisors of both       *)
(*   forward all four. "SEGV" is a fault of the daemon, "KILL" SIGKILL.    *)
(* - The supervisor's handler for "ABRT", linux_pidns_forward_sent(), is   *)
(*   the forwarder: its branch for a fault the kernel raises for the       *)
(*   supervisor itself is not modelled, as the supervisor has no faults.   *)
(* - The daemon is one process with the steps that matter for signals: the *)
(*   child's sigprocmask(), its prctl(PR_SET_PDEATHSIG, SIGTERM) and its   *)
(*   poll() of the lifeline in the prefork                                 *)
(*   (linux_pidns_arm_parent_death()), for CUSE the start of the thread    *)
(*   that watches the lifeline (esdm_cuse_supervisor_watch()), its         *)
(*   sigaction()s after it (the server's                                   *)
(*   esdm_shm_status_install_signal_suspend(); the CUSE daemons installed  *)
(*   their handler there before the fix), for CUSE the session setup that  *)
(*   sets esdm_cuse_session, the privilege drop (the server's              *)
(*   drop_privileges_permanent(), the CUSE daemons'                        *)
(*   drop_privileges_transient()), for the server the second               *)
(*   linux_pidns_arm_parent_death(), then serving. A termination handler   *)
(*   makes it exit with 0: the server's latches server_exit at any time,   *)
(*   the CUSE one esdm_cuse_exit_requested (Latch); without the latch it   *)
(*   acts only once the session exists. The daemon may also exit with 1,   *)
(*   fault or be killed by SIGKILL at any time.                            *)
(* - The parent-death signal: when the supervisor ends while the daemon    *)
(*   lives and has it set, the kernel sends the daemon SIGTERM, which the  *)
(*   namespace init receives if it blocks it or has a handler for it. A    *)
(*   supervisor that ended before the prctl() sends nothing. A change of   *)
(*   the effective user or group ID clears the setting.                    *)
(* - The lifeline: a pipe whose write end only the supervisor holds. The   *)
(*   daemon's poll() of the read end tells whether the supervisor ended,   *)
(*   at any time and whatever its user ID. The daemon that finds it ended  *)
(*   sends SIGTERM to itself, which the namespace init receives as above.  *)
(*   The server polls after each prctl() and arms the signal again after   *)
(*   its drop, which is its last change of the IDs. The CUSE daemons       *)
(*   change the effective user ID again for every privileged ioctl: a      *)
(*   thread of theirs blocks in poll() instead, from before the first      *)
(*   change on. Before the fix (FixPdeath = FALSE) there is no lifeline.   *)
(* - SIGKILL to the supervisor (KillAt) also stands for what else ends it  *)
(*   and no handler can prevent: the two real-time signals the C library   *)
(*   keeps for itself, for which sigaction() fails, and a fault of its     *)
(*   own.                                                                  *)
(* - A handler's kill() and its return are one step.                       *)
(* - The caller's signal mask is empty, so the child's                     *)
(*   sigprocmask(SIG_SETMASK, &old_mask) and the supervisor's              *)
(*   sigprocmask(SIG_UNBLOCK, &fwd_set) both leave nothing blocked. No     *)
(*   disposition is SIG_IGN but SIGCHLD's (ChldIgn) and those of           *)
(*   PreIgnored: the server's install_term() ignores SIGUSR1 until the     *)
(*   suspend handler is installed.                                         *)
(* - Not modelled: unshare() and fork() failing, stop signals, the threads *)
(*   of the daemon but the one that watches the lifeline (the              *)
(*   parent-death signal is a setting of the thread that called prctl(),   *)
(*   the main thread, which lives as long as the daemon, and cleared in    *)
(*   every thread by the change of the IDs), the privileged ioctls of a    *)
(*   CUSE daemon (the drop cleared the setting, they change nothing),      *)
(*   signals sent to the daemon directly.                                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Sigs,         \* catchable signals sent: "TERM", "USR1", "USR2", "ABRT"
    Fwd,          \* fwd_signals[], the signals the supervisor forwards
    PreHandlers,  \* handlers the caller installs before the prefork
    PreIgnored,   \* signals the caller ignores before the prefork
    PostHandlers, \* handlers the daemon installs after it
    TermSigs,     \* handlers that make the daemon terminate
    Latch,        \* a termination handler acts before the daemon serves
    Callback,     \* supervisor_exit_cb is set
    SendSigs,     \* signals others send to the supervisor
    MaxSends,     \* how many
    Fates,        \* how the daemon may end on its own: "exit1", "SEGV", "KILL"
    Checked,      \* signals that must reach the daemon's handler
    Handled,      \* the same, once the daemon installed their handler
    FwdDrops,     \* mutation: signals the forwarder does not pass on
    KillAt,       \* steps of the daemon before which SIGKILL may end the
                  \* supervisor: values of cpc
    ChldIgn,      \* SIGCHLD is inherited as SIG_IGN
    Unblocked,    \* the code before 9a53de9d: Fwd not blocked across fork()
    FixChld,      \* fix: SIGCHLD to SIG_DFL across fork()
    FixReap,      \* fix: waitid(WNOWAIT), block Fwd, clear the PID, reap
    FixPdeath,    \* fix: the lifeline, polled after each prctl(); after the
                  \* drop the signal armed again or the lifeline watched
    Watch         \* with FixPdeath: a thread watches the lifeline (CUSE);
                  \* else the signal is armed again after the drop (server)

SDom == Sigs \cup {"SEGV"}
Faults == {"SEGV", "KILL"}
DaemonSet == PreHandlers \cup PostHandlers
SPcs == {"sigprocmask_block", "sigaction_chld", "fork", "store_child",
         "sigaction", "sigprocmask_unblock", "waitid", "sigprocmask_block2",
         "clear_child", "waitpid", "supervisor_exit_cb", "signal", "raise",
         "exit_128", "exit", "exit_failure"}

VARIABLES
    \* supervisor
    spc,      \* main code
    sstack,   \* handler frames, the innermost last
    slife,    \* "alive", "dead"
    smask,
    spend,
    sdisp,    \* "DFL", "IGN", "caller" (the daemon's handler), "fwd"
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
    cpdeath,  \* PR_SET_PDEATHSIG is set
    cwatch,   \* a thread blocks in poll() on the lifeline
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
cv == <<clife, cpc, cmask, cpend, chand, cstop, cstatus, cpdeath, cwatch>>
vars == <<sv, cv, sent, reused, owed, stopReq, viol>>

Init ==
    /\ spc = "sigprocmask_block"
    /\ sstack = <<>>
    /\ slife = "alive"
    /\ smask = {}
    /\ spend = {}
    /\ sdisp = [s \in SDom |-> IF s \in PreHandlers THEN "caller"
                             ELSE IF s \in PreIgnored THEN "IGN" ELSE "DFL"]
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
    /\ cpdeath = FALSE
    /\ cwatch = FALSE
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

\* The supervisor ends: the kernel sends the parent-death signal to a living
\* daemon that has it set, and the namespace init takes it like any other
PDeath ==
    cpend' = IF /\ clife = "alive" /\ cpdeath
                /\ ("TERM" \in cmask \/ "TERM" \in chand)
             THEN cpend \cup {"TERM"} ELSE cpend

\* kill(getpid(), SIGTERM) by the daemon that found the lifeline hung up: the
\* namespace init takes its own signal only with a handler, or blocked
SelfTerm ==
    cpend' = IF "TERM" \in cmask \/ "TERM" \in chand
             THEN cpend \cup {"TERM"} ELSE cpend

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

\* sigprocmask(SIG_BLOCK, &fwd_set, &old_mask)
SBlock ==
    /\ SMainOK /\ spc = "sigprocmask_block"
    /\ smask' = IF Unblocked THEN smask ELSE smask \cup Fwd
    /\ spc' = IF FixChld THEN "sigaction_chld" ELSE "fork"
    /\ UNCHANGED <<sstack, slife, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fix: sigaction(SIGCHLD, SIG_DFL, &sa_chld), restored in the child
SChld ==
    /\ SMainOK /\ spc = "sigaction_chld"
    /\ schld' = "DFL"
    /\ spc' = "fork"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* fork(): the child is PID 1 of the namespace, with the supervisor's mask
\* and dispositions and none of its pending signals
SFork ==
    /\ SMainOK /\ spc = "fork"
    /\ spc' = "store_child"
    /\ clife' = "alive"
    /\ cpc' = "sigprocmask"
    /\ cmask' = smask
    /\ cpend' = {}
    /\ chand' = {s \in Sigs : sdisp[s] = "caller"}
    /\ cstop' = sflag
    /\ UNCHANGED <<cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<sent, reused, owed, stopReq, viol>>

\* linux_pidns_child = pid
SStore ==
    /\ SMainOK /\ spc = "store_child"
    /\ child' = 1
    /\ spc' = "sigaction"
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* sigaction(fwd_signals[i], &sa, NULL) with linux_pidns_forward_signal(),
\* sa_mask = fwd_set and SA_RESTART, one signal per step
SSigaction ==
    /\ SMainOK /\ spc = "sigaction"
    /\ LET s == CHOOSE x \in todo : TRUE IN
       /\ sdisp' = [sdisp EXCEPT ![s] = "fwd"]
       /\ todo' = todo \ {s}
       /\ spc' = IF todo = {s} THEN "sigprocmask_unblock" ELSE "sigaction"
    /\ UNCHANGED <<sstack, slife, smask, spend, schld, sflag, child, wst,
                   raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* sigprocmask(SIG_UNBLOCK, &fwd_set, NULL)
SUnblock ==
    /\ SMainOK /\ spc = "sigprocmask_unblock"
    /\ smask' = smask \ Fwd
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

\* waitpid(pid, &status, 0) reaps the daemon; ECHILD if the kernel did, then
\* exit(EXIT_FAILURE)
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
    /\ UNCHANGED <<cpc, cmask, cpend, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sent, reused, owed, stopReq, viol>>

\* supervisor_exit_cb(): supervisor_exit(), esdm_rpc_server_cleanup()
SCallback ==
    /\ SMainOK /\ spc = "supervisor_exit_cb"
    /\ cbRuns' = cbRuns + 1
    /\ viol' = IF clife \in {"zombie", "reaped"} THEN viol
               ELSE viol \cup {"CleanupEarly"}
    /\ spc' = AfterCb(wst)
    /\ UNCHANGED <<sstack, slife, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq>>

\* signal(sig, SIG_DFL), which fails for SIGKILL, and
\* sigprocmask(SIG_UNBLOCK) of sig alone
SSignal ==
    /\ SMainOK /\ spc = "signal"
    /\ sdisp' = IF wst \in SDom THEN [sdisp EXCEPT ![wst] = "DFL"] ELSE sdisp
    /\ smask' = smask \ {wst}
    /\ spc' = "raise"
    /\ UNCHANGED <<sstack, slife, spend, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* raise(sig)
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

\* exit(128 + sig), exit(WEXITSTATUS(status)), exit(EXIT_FAILURE)
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
                  /\ smask' = smask \cup Fwd \cup {s}
                  /\ UNCHANGED <<slife, how, sfinal, sflag, cpend, owed, viol>>
             [] sdisp[s] = "caller" ->
                  \* the daemon's handler, run in the supervisor: before
                  \* fork() the server's flag passes to the daemon
                  /\ IF Latch /\ s \in TermSigs /\ clife = "unborn"
                     THEN /\ sflag' = TRUE
                          /\ owed' = owed \ {s}
                          /\ UNCHANGED viol
                     ELSE /\ Lose(s)
                          /\ UNCHANGED sflag
                  /\ UNCHANGED <<sstack, smask, slife, how, sfinal, cpend>>
             [] sdisp[s] = "IGN" ->
                  /\ Lose(s)
                  /\ UNCHANGED <<sstack, smask, slife, how, sfinal, sflag,
                                 cpend>>
             [] OTHER ->
                  \* SIG_DFL terminates
                  /\ slife' = "dead"
                  /\ PDeath
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
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sent, reused, stopReq>>

Top == sstack[Len(sstack)]

\* linux_pidns_forward_signal(): child = linux_pidns_child
SFwdLoad ==
    /\ slife = "alive" /\ sstack # <<>> /\ spend \ smask = {}
    /\ Top.pc = "fwd_load"
    /\ sstack' = [sstack EXCEPT ![Len(sstack)] =
                      [Top EXCEPT !.pc = "fwd_kill", !.ch = child]]
    /\ UNCHANGED <<spc, slife, smask, spend, sdisp, schld, sflag, todo, child,
                   wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, sent, reused, owed, stopReq, viol>>

\* if (child > 0) kill(child, sig), and the handler's return
SFwdKill ==
    /\ slife = "alive" /\ sstack # <<>> /\ spend \ smask = {}
    /\ Top.pc = "fwd_kill"
    /\ sstack' = SubSeq(sstack, 1, Len(sstack) - 1)
    /\ smask' = Top.om
    /\ IF Top.sig \in FwdDrops THEN UNCHANGED <<cpend, owed, viol>>
       ELSE IF Top.ch # 0 THEN Kill(Top.sig)
       ELSE IF clife \in {"unborn", "alive"}
            THEN Lose(Top.sig) /\ UNCHANGED cpend
            ELSE UNCHANGED <<cpend, owed, viol>>
    /\ UNCHANGED <<spc, slife, spend, sdisp, schld, sflag, todo, child, wst,
                   raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sent, reused, stopReq>>

SNext ==
    \/ SDeliver \/ SFwdLoad \/ SFwdKill
    \/ SBlock \/ SChld \/ SFork \/ SStore \/ SSigaction \/ SUnblock
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
    /\ UNCHANGED <<cpc, cmask, cpend, chand, cstop, cpdeath, cwatch>>
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
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, stopReq>>

\* the child's sigaction(SIGCHLD, &sa_chld, NULL) and
\* sigprocmask(SIG_SETMASK, &old_mask, NULL)
CUnmask ==
    /\ CReady /\ cpc = "sigprocmask"
    /\ cmask' = {}
    /\ cpc' = "prctl"
    /\ UNCHANGED <<clife, cpend, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* prctl(PR_SET_PDEATHSIG, SIGTERM) of linux_pidns_arm_parent_death(): in
\* the prefork child and, for the server, again after the drop. The kernel
\* sends nothing for a supervisor that ended before it; before the fix the
\* daemon had no means to tell.
CPrctl ==
    /\ CReady /\ cpc \in {"prctl", "prctl2"}
    /\ cpdeath' = TRUE
    /\ cpc' = IF ~FixPdeath THEN "sigaction"
              ELSE IF cpc = "prctl" THEN "poll" ELSE "poll2"
    /\ UNCHANGED <<clife, cmask, cpend, chand, cstop, cstatus, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* fix: its poll() of the lifeline - a supervisor that ended before the
\* prctl() is found, and the daemon sends itself what the kernel did not
CPoll ==
    /\ CReady /\ cpc \in {"poll", "poll2"}
    /\ IF slife = "dead" THEN SelfTerm ELSE UNCHANGED cpend
    /\ cpc' = IF cpc = "poll2" THEN "serve"
              ELSE IF Watch THEN "pthread_create" ELSE "sigaction"
    /\ UNCHANGED <<clife, cmask, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* fix, CUSE: thread_start_detached(esdm_cuse_supervisor_watch), while the
\* signal of the prefork is still armed
CWatchStart ==
    /\ CReady /\ cpc = "pthread_create"
    /\ cwatch' = TRUE
    /\ cpc' = "sigaction"
    /\ UNCHANGED <<clife, cmask, cpend, chand, cstop, cstatus, cpdeath>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* fix, CUSE: linux_pidns_watch_supervisor() in that thread - poll() returns
\* once the supervisor ended, then kill(getpid(), SIGTERM). The thread runs
\* whatever the main code does.
CWatch ==
    /\ clife = "alive" /\ cwatch /\ slife = "dead"
    /\ SelfTerm
    /\ cwatch' = FALSE
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstop, cstatus, cpdeath>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* the daemon's sigaction()s after the prefork
CSigaction ==
    /\ CReady /\ cpc = "sigaction"
    /\ chand' = chand \cup PostHandlers
    /\ cpc' = IF Latch THEN "setuid" ELSE "cuse_lowlevel_setup"
    /\ UNCHANGED <<clife, cmask, cpend, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* esdm_cuse_session = cuse_lowlevel_setup()
CSetup ==
    /\ CReady /\ cpc = "cuse_lowlevel_setup"
    /\ cpc' = "setuid"
    /\ UNCHANGED <<clife, cmask, cpend, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* drop_privileges_permanent() or drop_privileges_transient(): the kernel
\* clears the parent-death signal with the change of the IDs. The server
\* arms it again (fix); a CUSE daemon, which goes on changing them, has
\* the thread that watches the lifeline.
CDrop ==
    /\ CReady /\ cpc = "setuid"
    /\ cpdeath' = FALSE
    /\ cpc' = IF FixPdeath /\ ~Watch THEN "prctl2" ELSE "serve"
    /\ UNCHANGED <<clife, cmask, cpend, chand, cstop, cstatus, cwatch>>
    /\ UNCHANGED <<sv, sent, reused, owed, stopReq, viol>>

\* a termination handler ran: the daemon tears down and returns 0
CStopExit == CReady /\ cstop /\ CExit("exit0")

\* it fails, faults or is killed by SIGKILL
CFate == clife = "alive" /\ \E f \in Fates : CExit(f)

CNext ==
    \/ CDeliver \/ CUnmask \/ CPrctl \/ CPoll \/ CWatchStart \/ CWatch
    \/ CSigaction \/ CSetup \/ CDrop \/ CStopExit

-----------------------------------------------------------------------------
(* Environment *)

\* kill(supervisor, s) by systemd, esdm-server-signal-helper or anybody;
\* owed to the daemon once the prefork began and while it may live, a signal
\* of Handled once the daemon has its handler
ESend ==
    /\ slife = "alive" /\ sent < MaxSends
    /\ \E s \in SendSigs :
        LET arm == spc # "sigprocmask_block" /\ clife \in {"unborn", "alive"}
            owe == \/ arm /\ s \in Checked
                   \/ clife = "alive" /\ s \in Handled /\ s \in chand
        IN /\ spend' = spend \cup {s}
           /\ owed' = IF owe THEN owed \cup {s} ELSE owed
           /\ stopReq' = (stopReq \/ (arm /\ s \in TermSigs))
    /\ sent' = sent + 1
    /\ UNCHANGED <<spc, sstack, slife, smask, sdisp, schld, sflag, todo,
                   child, wst, raised, how, sfinal, cbRuns>>
    /\ UNCHANGED <<cv, reused, viol>>

\* SIGKILL to the supervisor while the daemon lives: nothing forwards the
\* signals it was sent any more
EKill ==
    /\ slife = "alive" /\ clife = "alive" /\ cpc \in KillAt
    /\ slife' = "dead"
    /\ how' = "signal"
    /\ sfinal' = "KILL"
    /\ PDeath
    /\ owed' = {}
    /\ UNCHANGED <<spc, sstack, smask, spend, sdisp, schld, sflag, todo,
                   child, wst, raised, cbRuns>>
    /\ UNCHANGED <<clife, cpc, cmask, chand, cstop, cstatus, cpdeath, cwatch>>
    /\ UNCHANGED <<sent, reused, stopReq, viol>>

\* the reaped PID goes to a new process
EReuse ==
    /\ clife = "reaped" /\ ~reused
    /\ reused' = TRUE
    /\ UNCHANGED <<sv, cv, sent, owed, stopReq, viol>>

\* The daemon serves and has nothing to act on
DaemonIdle ==
    clife = "alive" /\ cpc = "serve" /\ ~cstop /\ cpend \ cmask = {}

\* The final states. Nothing is left to do: the supervisor ended and the
\* daemon ended, was never forked or serves on without it, which it only
\* does with no parent-death signal armed and no thread at the lifeline; or
\* the supervisor waits for a daemon that serves. Done is enabled in no
\* other state, so that TLC reports every other state without a successor
\* as a deadlock.
Final ==
    \/ /\ slife = "dead"
       /\ (clife # "alive" \/ (DaemonIdle /\ ~cpdeath /\ ~cwatch))
    \/ /\ slife = "alive" /\ spc \in {"waitpid", "waitid"}
       /\ sstack = <<>> /\ spend \ smask = {}
       /\ DaemonIdle

Done == Final /\ UNCHANGED vars

Next == SNext \/ CNext \/ CFate \/ ESend \/ EKill \/ EReuse \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(SNext) /\ WF_vars(CNext)

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ spc \in SPcs
    /\ slife \in {"alive", "dead"}
    /\ smask \subseteq SDom /\ spend \subseteq SDom
    /\ sdisp \in [SDom -> {"DFL", "IGN", "caller", "fwd"}]
    /\ child \in {0, 1}
    /\ Len(sstack) <= Cardinality(SDom)
    /\ clife \in {"unborn", "alive", "zombie", "reaped"}
    /\ cpc \in {"none", "sigprocmask", "prctl", "poll", "pthread_create",
                "sigaction", "cuse_lowlevel_setup", "setuid", "prctl2",
                "poll2", "serve"}
    /\ cpdeath \in BOOLEAN
    /\ cwatch \in BOOLEAN
    /\ cmask \subseteq Sigs /\ cpend \subseteq Sigs /\ chand \subseteq Sigs
    /\ owed \subseteq Checked \cup Handled

\* A signal of Checked sent to the supervisor once the prefork began
\* reaches the daemon's handler unless the daemon ends first: no handler
\* of the supervisor takes it, the supervisor does not die by it, the
\* kernel does not discard it at the namespace init.
NoLostSignal == "Lost" \notin viol

\* A signal owed to the daemon is on its way: pending at the supervisor, in
\* a forwarder or pending at the daemon. A forwarder that returns without
\* its kill() violates it, as does every other silent drop.
OwedInFlight ==
    \A s \in owed :
        \/ s \in spend
        \/ \E i \in 1..Len(sstack) : sstack[i].sig = s
        \/ s \in cpend

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

\* ... nor does any other signal a handler can catch. SIGKILL does: see
\* OrphanStops.
NoOrphan == "Orphan" \notin viol

\* Outside the final states the supervisor or the daemon can take a step.
\* The deadlock check alone does not show a hang of the two while the
\* environment can still step: a signal left to send, the fate of the
\* daemon, the reuse of its PID.
NoHang == Final \/ ENABLED (SNext \/ CNext)

-----------------------------------------------------------------------------
(* Liveness *)

\* The supervisor ends once the daemon did.
SupervisorExits ==
    (slife = "alive" /\ clife \in {"zombie", "reaped"}) ~> (slife = "dead")

\* A signal owed to the daemon reaches it or the daemon ends.
OwedReaches == \A s \in Checked \cup Handled : (s \in owed) ~> (s \notin owed)

\* A daemon that outlives its supervisor ends: the parent-death signal
\* stops it, or the signal it sends itself once it found the lifeline hung
\* up. Before the fix this held only for a supervisor that ended after the
\* daemon's prctl() and before its privilege drop.
OrphanStops == (slife = "dead" /\ clife = "alive") ~> (clife # "alive")

\* A termination signal sent to the supervisor ends both.
StopEndsBoth ==
    stopReq ~> (slife = "dead" /\ clife \in {"zombie", "reaped"})

=============================================================================
