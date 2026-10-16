#import "../template.typ": *

= Scheduler Entropy Source Assessment <sec:sched-assessment>

An entropy assessment of the scheduler-based entropy sources is not provided
yet. Both are therefore credited with no entropy by default:

- The scheduler entropy source of the kernel module addon/linux\_esdm\_es
  (section @sec:sched-events) is not built by default (`BUILD_ES_SCHED=0` in
  the Makefile of the module), and the ESDM credits it with no entropy
  (`es_sched_entropy_rate` is 0). The module processes its time stamps like
  those of the interrupt entropy source (chapter @sec:irq-assessment): health
  tests, per-CPU event ring and the conditioning with the DRBG of the module.
  Built with `BUILD_TESTING=1`, the module provides the raw time stamp
  differences in `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires` - the
  default interface `esdm-getrawentropy` reads - and records the first 1,024
  events after loading with the module parameter
  `boot_raw_sched_hires_test=1`. The steps of section @sec:90b-reuse apply to
  this data likewise.

- The eBPF-based scheduler entropy source (`es_sched_ebpf`, section
  @sec:ebpf) is disabled by default, and its entropy rate
  `es_sched_ebpf_entropy_rate` is 0. addon/es\_ebpf\_testing provides the
  measurement tooling for it: `esdm-ebpf-collect` records the time
  differences of successive scheduling events of one CPU,
  `analyze_non_iid.sh` performs the SP800-90B assessment of them and
  `analyze_restart.sh` the restart test of SP800-90B section 3.1.4. The README
  of that directory derives the entropy rate and the oversampling rate
  (`es_sched_ebpf_osr`) to configure from the measured min-entropy per event,
  to be determined for every deployment environment.
