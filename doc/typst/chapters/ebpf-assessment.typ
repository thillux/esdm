#import "../template.typ": *
#import "../plots/histogram.typ": histogram

= eBPF Entropy Source Assessment <sec:ebpf-assessment>

This chapter is for auditors and for integrators who run the #ac("ESDM") on a
stock Linux kernel. It assesses the #acs("eBPF")-based interrupt and scheduler
entropy sources (meson options `es_irq_ebpf` and `es_sched_ebpf`, section
@sec:ebpf) against #ac("SP") 800-90B. They observe events similar to those of
the entropy sources of chapter @sec:kernel-es-assessment, but with other hooks,
another clock and another conditioning component. The chapter therefore assesses
the differences and refers to chapter @sec:kernel-es-assessment for the rest.
The measurements of section @sec:ebpf-measurements show what the assessment
yields in a #ac("KVM") guest; they provide no entropy rate for another system.
By default, the #ac("ESDM") credits neither entropy source
(`es_irq_ebpf_entropy_rate=0`, `es_sched_ebpf_entropy_rate=0`): the integrator
must determine the rates in the deployment environment.

== Differences from the Kernel Module <sec:ebpf-differences>

Table @tab:ebpf-differences compares the #ac("eBPF") entropy sources with those
of the kernel module `esdm_es`.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(left + top)
    table(
      columns: (1fr, 1.6fr, 1.6fr),
      table.header(
        [], [Kernel module `esdm_es`], [#ac("eBPF", cap: true) entropy sources],
        table.hline(stroke: 0.8pt),
      ),
      [Scheduler event], [Task wakeup (`ttwu_stat`)],
        [Context switch (`tp_btf/sched_switch`)],
      [Interrupt event], [Interrupt (`add_interrupt_randomness`)],
        [Entry of an interrupt handler (`tp_btf/irq_handler_entry`)],
      [Kernel], [Hook patches], [Stock kernel with #ac("BTF"), libbpf 1.2 or
      later], [Timestamp], [`random_get_entropy`, a cycle counter],
        [`bpf_ktime_get_ns`, the monotonic clock in nanoseconds],
      [#ac("GCD", cap: true)], [One, of the first 100 timestamps],
        [One per #ac("CPU"), of its first 100 timestamps],
      [Collected value], [Timestamp], [Delta to the preceding timestamp of
        the #ac("CPU")],
      [Health tests], [Stuck test always; #ac("RCT"), #ac("APT") and startup
      test with
        `fips=1`; over all #ac("CPU", pl: true)],
        [All tests in #ac("FIPS") mode, #ac("SP") 800-90C mode or with the NTG.1
        seeding strategy; per #ac("CPU")],
      [Oversampling rate], [`ESDM_ES_OSR` of the Makefile, default 3],
        [`es_irq_ebpf_osr`, `es_sched_ebpf_osr`, default 1],
      [Credit per event], [1/`ESDM_ES_OSR` bits],
        [$min("rate" \/ 4, 1 \/ "OSR")$ bits with the entropy rate of
        `es_irq_ebpf_entropy_rate` or `es_sched_ebpf_entropy_rate`],
      [Conditioning], [#ac("DRBG", cap: true) instance in the kernel module],
        [XDRBG-256 pool in the #ac("ESDM") server],
      [Raw data], [debugfs, all #ac("CPU", pl: true), runs of up to 128 deltas],
        [`esdm-ebpf-collect`, one #ac("CPU"), every delta],
      [Restart], [Load of the kernel module],
        [Load of the #ac("eBPF") programs],
    )
  },
  caption: [The #ac("eBPF") entropy sources compared with the kernel module],
) <tab:ebpf-differences>

The scheduler entropy sources thus observe different events: the kernel
module timestamps the wakeup of a task, the #ac("eBPF") program the switch of a
#ac("CPU") from one task to another. A wakeup often leads to a context switch,
but a context switch also happens when a task blocks, yields or is preempted.
The interrupt entropy sources observe the same interrupts; the #ac("eBPF")
program fires once per interrupt handler, i.e. several times for an interrupt
line that devices share.

== SP 800-90B Assessment <sec:ebpf-90b>

The assessment of chapter @sec:kernel-es-assessment applies to the #ac("eBPF")
entropy sources with the following differences. With them, the #ac("eBPF")
entropy sources meet the requirements of #ac("SP") 800-90B and #ac("FIPS") 140-3
#ac("IG") D.J that chapter @sec:kernel-es-assessment discusses.

#paragraph[Noise sources][#ac("SP", cap: true) 800-90B sections 3.1.6 and 3.2.2:
each #ac("eBPF") entropy source has one noise source, the timing of context
switches or of the entry of interrupt handlers. The four interrupt and scheduler
entropy sources observe related events, so the #ac("ESDM") credits at most one
of them (section @sec:kernel-es-overview).]

#paragraph[Raw data][#ac("SP", cap: true) 800-90B sections 3.1.1 and 3.2.1
requirements 5 and 6, #ac("IG") D.J additional comment 1: the tool
`esdm-ebpf-collect` of `tests/es_ebpf_testing`, built with the meson option
`es_ebpf_testing`, loads its own copy of the #ac("eBPF") programs with the
health tests off and writes every delta of the assessed #ac("CPU"), as the
program computes it for the collection. It refuses to run in #ac("FIPS") mode,
and the #ac("ESDM") server never records raw data. Two properties keep the tool
from changing what it measures: it drains the ring buffer every 50 ms instead of
being woken up for every delta, and it moves itself off the assessed #ac("CPU").
Otherwise, each of its own context switches would be an event of the scheduler
entropy source, which in turn would wake the tool up. The README of
`tests/es_ebpf_testing` documents the procedure; `analyze_non_iid.sh` and
`analyze_restart.sh` perform the assessments.]

#paragraph[Restart][#ac("SP", cap: true) 800-90B section 3.1.4: a restart is one
run of `esdm-ebpf-collect`. It loads and attaches the #ac("eBPF") programs,
which start with zeroed per-#acs("CPU") state – no #ac("GCD"), no preceding timestamp – as when the #ac("ESDM") server starts its entropy sources. The matrix
holds the 8 least significant bits of the first 1,000 deltas of the assessed
#ac("CPU") in each of 1,000 runs, one row per run.]

#paragraph[Conditioning][#ac("SP", cap: true) 800-90B section 3.1.5, #ac("IG")
D.J additional comment 3: the conditioning component is the XDRBG-256 pool of
the #ac("ESDM") server (section @sec:dp-ebpf), a vetted conditioning component
over SHAKE256 with an internal width of 512 bits. The deltas are the seed of its
next reseed; an extraction reseeds it and generates at most the security
strength of 256 bits. Equation @eq:vetted applies: the output carries
$min(h_"in", 256)$ bits of entropy, where $h_"in"$ is the entropy the #ac("ESDM")
credits for the inserted deltas.]

#paragraph[Entropy rate][#ac("SP", cap: true) 800-90B section 3.1.3, #ac("IG")
D.J additional comment
6: the #ac("ESDM") credits $min("rate" \/ 4, 1 \/ "OSR")$ bits per delta, where
$"rate"$ is the entropy rate per 256 bits of data, i.e. four deltas of 64 bits,
and $"OSR"$ is the oversampling rate. For a measured min-entropy $H$ per delta,
the README of
`tests/es_ebpf_testing` derives the entropy rate $floor(H dot 256 \/ 64)$,
capped at $4 \/ "OSR"$, and the oversampling rate $"OSR" = ceil(1 \/ H)$.
With an oversampling rate of 1, the most precise setting, the #ac("ESDM")
credits at most 1 bit per delta, however high the measured min-entropy is.]

#paragraph[Health tests][#ac("SP", cap: true) 800-90B sections 4.3 and 4.4: the
#ac("eBPF") programs implement the stuck test, the #ac("RCT"), the #ac("APT")
and the startup test of section @sec:health-tests with the cut-off values of
`kernel/shared/esdm_health_cutoffs.h` for the configured oversampling rate.
Each #ac("CPU") runs its own instance of the tests on its own events, which is
at least as strict as the tests over all #ac("CPU", pl: true) of the kernel
module. The tests run in #ac("FIPS") mode, in #ac("SP") 800-90C mode and with
the NTG.1 seeding strategy. A failure discards the collected deltas and restarts
the startup test; after a permanent failure, the #ac("ESDM") no longer credits
the entropy source until it is reset, and its self test fails.]

== eBPF Entropy Source Measurements <sec:ebpf-measurements>

The measurements in this section used the tooling of `tests/es_ebpf_testing`
in the #ac("KVM") guest of section @sec:kvm-measurements. They describe this
system only: they show what the assessment of the #ac("eBPF") entropy sources
yields and how its results translate into the configuration, but they provide no
entropy rate to configure on another system. By default, the #ac("ESDM") still
credits both entropy sources with no entropy.

=== Test Environment and Raw Data <sec:ebpf-kvm>

- The guest of section @sec:kvm-measurements ran the stock Linux 7.3.4,
  without the hook patches, and an #ac("ESDM") built with `es_irq_ebpf`,
  `es_sched_ebpf` and `es_ebpf_testing`.

- All assessments ran on #ac("CPU") 0. The network interrupts of the guest went
  to #ac("CPU") 0, so that the flood reached it.

- `esdm-ebpf-collect` reads the timestamps with `bpf_ktime_get_ns()` like
  the deployed entropy sources, so the deltas are in nanoseconds of the
  clock source `tsc`, i.e. the #ac("TSC") of the host converted by the
  timekeeping of the guest (section @sec:kvm-measurements). It wrote them to a
  tmpfs file system, so that storing the data generated no block #ac("I/O")
  interrupts.

- The load profiles are those of section @sec:kvm-measurements: idle, load
  and flood for the interrupt entropy source, idle, load and switch for the
  scheduler entropy source. The idle collections were limited to 15 minutes
  for the interrupt and to 3 hours for the scheduler entropy source.

- The analysis follows `analyze_non_iid.sh`: `esdm-extractlsb` with the mask
  `FF` keeps the 8 #ac("LSB") of every delta, and `ea_non_iid` of the
  #ac("NIST") #ac("SP") 800-90B entropy assessment tool, version 1.1.8,
  processes them with 8 bits per symbol.

Table @tab:ebpf-stats lists the statistical properties of the raw noise
source data in the form of section @sec:raw-distribution; figures
@fig:kvm-ebpf-irq-flood to @fig:kvm-ebpf-sched-switch show three of the
distributions.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  show table.cell.where(x: 0): set align(left + top)
  table(
    columns: (2.3fr,) + (1fr,) * 8,
    table.header(
      [Data Set], [25% Quar\u{AD}tile], [Median], [Mean],
      [75% Quar\u{AD}tile], [Std. Dev.], [Var. Coeff.], [$chi^2$ P],
      [$chi^2$ #ac("DF")],
      table.hline(stroke: 0.8pt),
    ),
    [Interrupt, load],
      [63], [127], [127.39], [191], [73.87], [0.58], [0.1851], [255],
    [Interrupt, flood],
      [64], [128], [127.65], [192], [73.85], [0.58], [0.3981], [255],
    [Scheduler, idle],
      [63], [127], [127.55], [192], [73.95], [0.58], [0.4766], [255],
    [Scheduler, load],
      [63], [127], [127.17], [191], [74.08], [0.58], [0.0007], [255],
    [Scheduler, switch],
      [70], [139], [133.25], [196], [73.47], [0.55], [0], [255],
  )
}
, caption: [Statistical properties of the raw noise source data of the
#ac("eBPF")
  entropy sources in a #ac("KVM") guest]) <tab:ebpf-stats>

#figure(
  histogram("kvm-ebpf-irq-flood"),
  caption: [#ac("eBPF", cap: true) Interrupt Entropy Source, #ac("KVM") Guest,
  Flood:
    Raw Noise Source Data Distribution],
) <fig:kvm-ebpf-irq-flood>

#figure(
  histogram("kvm-ebpf-sched-idle"),
  caption: [#ac("eBPF", cap: true) Scheduler Entropy Source, #ac("KVM") Guest,
  Idle:
    Raw Noise Source Data Distribution],
) <fig:kvm-ebpf-sched-idle>

#figure(
  histogram("kvm-ebpf-sched-switch"),
  caption: [#ac("eBPF", cap: true) Scheduler Entropy Source, #ac("KVM") Guest,
  Switch:
    Raw Noise Source Data Distribution],
) <fig:kvm-ebpf-sched-switch>

#paragraph[Interrupt entropy source][#ac("CPU", cap: true) 0 of the idle guest
received an interrupt about every 2.048 seconds. After the 100 timestamps that
determine the #ac("GCD"), the collection gathered 368 deltas in 15 minutes: too
few for an assessment. As in section @sec:kvm-measurements, an idle guest
leaves the interrupt entropy source almost without events. Under load and
under the flood, #ac("CPU") 0 received 926 and 17,921 interrupts per second,
with median deltas of 446,884 ns and 50,502 ns. The deltas are even and odd in
equal shares, and the $chi^2$ test does not reject the equi-distribution of
the 8 #ac("LSB").]

#paragraph[Scheduler entropy source][
#ac("CPU", cap: true) 0 of the idle guest switched 36 times per second. In 3
hours, the collection gathered 386,400 deltas, fewer than the 1,000,000 that
#ac("SP") 800-90B section 3.1.3 asks for. Their median is 107,878 ns, and the
$chi^2$ test does not reject the equi-distribution of the 8 #ac("LSB") (figure
@fig:kvm-ebpf-sched-idle).
Under load, #ac("CPU") 0
switched 15,432 times per second with a median delta of 10,015 ns, and the
8 #ac("LSB") come close to an equi-distribution. The context switch stressor
drove #ac("CPU") 0 to 126,582 context switches per second. Half of the deltas
then lie between 7,421 ns and 7,743 ns, a range of only 322 ns that the 8
#ac("LSB") wrap around barely more than once: the distribution is skewed (figure
@fig:kvm-ebpf-sched-switch). The min-entropy estimates of section
@sec:ebpf-min-entropy account for this.]

=== SP 800-90B Min-Entropy and Restart Tests <sec:ebpf-min-entropy>

Table @tab:ebpf-min-entropy lists the results of `ea_non_iid` in bits per
delta and the configuration they lead to according to the README of
`tests/es_ebpf_testing` (section @sec:ebpf-90b): the entropy rate
$floor(H dot 256 \/ 64)$, capped at $4 \/ "OSR"$, and the oversampling rate
$"OSR" = ceil(1 \/ H)$.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  show table.cell.where(x: 0): set align(left + top)
  table(
    columns: (1.8fr, 1.2fr) + (1fr,) * 6,
    table.header(
      [Data Set], [Deltas], [Deltas/s], [$H_"original"$],
      [$H_"bitstring"$], [$H$], [Rate], [#ac("OSR", cap: true)],
      table.hline(stroke: 0.8pt),
    ),
    [Interrupt, load],
      [1,000,000], [926], [7.882723], [0.908621], [7.268971], [4], [1],
    [Interrupt, flood],
      [1,000,000], [17,921], [7.353758], [0.895215], [7.161717], [4], [1],
    [Scheduler, idle],
      [386,400], [36], [7.805195], [0.900560], [7.204482], [4], [1],
    [Scheduler, load],
      [1,000,000], [15,432], [7.314320], [0.914111], [7.312891], [4], [1],
    [Scheduler, switch],
      [1,000,000], [126,582], [6.638383], [0.839417], [6.638383], [4], [1],
  )
}
, caption: [#ac("SP", cap: true) 800-90B min-entropy of the #ac("eBPF") entropy
sources in a #ac("KVM") guest,
  in bits per delta, and the resulting configuration]) <tab:ebpf-min-entropy>

Table @tab:ebpf-restart lists the restart tests in the guest, each validating
the estimate $H_I$ of the same load profile.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  show table.cell.where(x: 0): set align(left + top)
  table(
    columns: (1.8fr,) + (1fr,) * 5,
    table.header(
      [Restarts], [$H_I$], [$H_r$], [$H_c$],
      [Sanity check], [Validation],
      table.hline(stroke: 0.8pt),
    ),
    [Interrupt, load],
      [7.268971], [7.877176], [6.638383], [passed], [passed],
    [Interrupt, flood],
      [7.161717], [7.353758], [7.522373], [passed], [passed],
    [Scheduler, idle],
      [7.204482], [6.638399], [6.638383], [passed], [passed],
    [Scheduler, load],
      [7.312891], [7.353758], [7.353758], [passed], [passed],
    [Scheduler, switch],
      [6.638383], [7.353758], [7.353758], [passed], [passed],
  )
}
, caption: [#ac("SP", cap: true) 800-90B restart tests of the #ac("eBPF")
entropy sources in a #ac("KVM")
  guest, in bits per delta]) <tab:ebpf-restart>

All restart tests passed the sanity check and the validation test. They
support $min(H_r, H_c, H_I)$ bits per delta, at least 6.64 bits for every load
profile. The values 6.638383, 6.638399 and 7.353758, which recur in the
tables, are ceilings of the estimators for data sets of this size, as
section @sec:90b-314 explains: the lowest estimate of 6.64 bits is the value
an ideal source yields as well. The idle interrupt entropy source has no restart test: at one
interrupt every 2.048 seconds, one row of 1,000 deltas takes 34 minutes. At 36
context switches per second, one restart of the idle scheduler entropy source
takes about 30 seconds; its 1,000 restarts ran in four identical guests in
parallel, 250 each.

=== Configuration <sec:ebpf-config>

Every estimate of tables @tab:ebpf-min-entropy and @tab:ebpf-restart exceeds 1
bit per delta: the lowest is 6.64 bits. For both entropy sources and every
load profile, the configuration is thus the entropy rate 4 with the
oversampling rate 1: the accounting credits $min(4 \/ 4, 1 \/ 1) = 1$ bit per
delta, less than a fifth of the lowest estimate. An oversampling rate of 1 is
the most precise setting, so the configuration cannot express more.

In this guest, the measurements thus support `es_sched_ebpf_entropy_rate=4`
with `es_sched_ebpf_osr=1` and `es_irq_ebpf_entropy_rate=4` with
`es_irq_ebpf_osr=1`. They do not cover the interrupt entropy source of an idle
guest, which receives too few events to deliver entropy in useful time, and
they apply to no other system: the integrator must measure the deployment
environment. The #ac("ESDM") ships with both entropy rates at 0, and it credits
at most one of the four interrupt and scheduler entropy sources (section
@sec:kernel-es-overview).
