#import "../template.typ": *
#import "../plots/histogram.typ": histogram

// Unnumbered display equation (LaTeX equation*/displaymath).
#let display(body) = math.equation(block: true, numbering: none, body)
// "Output_Entropy" as used throughout the SP800-90B calculations: a word in
// the italic of the text, not a row of math italic letters.
#let OE = text(font: body-font, style: "italic")[Output\_Entropy]

= Interrupt and Scheduler Entropy Source Assessment <sec:kernel-es-assessment>

This chapter is for auditors. It assesses the interrupt and the scheduler
entropy sources of the Linux kernel module `esdm_es` (`kernel/esdm_es`)
against #ac("FIPS") 140-3 #ac("IG") D.J and #ac("SP") 800-90B. The two entropy
sources share their entire processing – timestamp, #ac("GCD"), health tests,
per-#acs("CPU") rings and #ac("DRBG") – and differ only in the event that
triggers a timestamp. The chapter therefore assesses them together and states
where they differ. The #ac("ESDM") treats all other entropy sources as black
boxes, so each of them needs an assessment of its own: chapter
@sec:ebpf-assessment assesses the #ac("eBPF") entropy sources, which observe
similar events on a stock kernel. The entropy sources of the auxiliary pool, the
Jitter #acs("RNG") and the #ac("CPU") entropy source are unrelated to the two
entropy sources of this chapter; the #ac("SP") 800-90C assessment in section
@sec:sp80090c covers their combination.

== Two Entropy Sources, One Processing <sec:kernel-es-overview>

The hook patches for the supported kernel versions invoke the kernel module
for every interrupt and for every task wakeup. The kernel module health tests
the timestamps, collects them in per-#acs("CPU") rings and conditions them with
a #ac("DRBG"). The #ac("ESDM") obtains the result with the
#ac("IOCTL", pl: true) of the device file `/dev/esdm_es` (sections
@sec:irq-processing and @sec:sched-events). Table @tab:kernel-es lists what
differs between the two entropy sources.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(left + top)
    table(
      columns: (1.1fr, 1.6fr, 1.6fr),
      table.header(
        [], [Interrupt entropy source], [Scheduler entropy source],
        table.hline(stroke: 0.8pt),
      ),
      [Event], [An interrupt handled by the kernel: hook in
        `add_interrupt_randomness`, patch
        `0002-ESDM-interrupt-entropy-source-hooks`],
        [A task wakeup: hook in `ttwu_stat`, called by `try_to_wake_up`,
        patch `0001-ESDM-scheduler-entropy-source-hooks`],
      [Kernel module build], [`BUILD_ES_IRQ=1` (default)],
        [`BUILD_ES_SCHED=1` (default 0)],
      [#ac("ESDM", cap: true) options], [`es_irq`, `es_irq_entropy_rate`
      (default 256)],
        [`es_sched`, `es_sched_entropy_rate` (default 0)],
      [Seed #ac("IOCTL")], [`ESDM_IRQ_ENT_BUF_IOCTL`], [`ESDM_SCHED_ENT_BUF_IOCTL`],
      [#ac("DRBG", cap: true) personalization], ["ESDM_IRQ_DRBG"], ["ESDM_SCH_DRBG"],
      [Raw data], [`/sys/kernel/debug/esdm_es/esdm_raw_hires`],
        [`/sys/kernel/debug/esdm_es/esdm_raw_sched_hires`],
      [Restart data], [module parameter `boot_raw_hires_test=1`],
        [module parameter `boot_raw_sched_hires_test=1`],
    )
  },
  caption: [What differs between the entropy sources of `esdm_es`],
) <tab:kernel-es>

Everything else is common code: both entropy sources read the timestamp
with `random_get_entropy`, divide it by the same #ac("GCD"), apply the same
health tests with the same cut-off values and credit
1/`ESDM_ES_OSR` bits per timestamp. Each of them keeps its own health test
state, rings and #ac("DRBG") instance.

#paragraph[Only one is credited][An interrupt often wakes up a task: the
handler of a network card wakes up the process waiting for the packet, a
timer interrupt wakes up the task whose sleep expired. The wakeup then
follows the interrupt by the latency of its handling, and both entropy
sources observe the same event. The #ac("ESDM") therefore credits at most one of
them – or of the #ac("eBPF") entropy sources of chapter @sec:ebpf-assessment:
the build refuses more than one non-zero rate of `es_irq_entropy_rate`,
`es_sched_entropy_rate`, `es_irq_ebpf_entropy_rate` and
`es_sched_ebpf_entropy_rate`, and a non-zero rate set at runtime sets the
others to zero (`esdm_config_timing_es_rate_set` in `esdm/esdm_config.c`).
The analysis of this chapter thus never adds the entropy of the two
entropy sources.]

== Noise Source Behavior <sec:noise-source>

The noise source component of an entropy source contains the
non-deterministic, entropy-producing activity. For the interrupt entropy
source, this activity is the arrival timing of interrupts; for the scheduler
entropy source, it is the timing of task wakeups. An analysis of the timestamps
characterizes the general behavior of the noise sources. The following
recap of the processing precedes this analysis:

- When an event occurs, the kernel module obtains a high-resolution timestamp
  with `random_get_entropy`. Technically, a cycle counter of the
  #ac("CPU") may produce this timestamp: it is unrelated to time, but
  increments at a high rate. At load time, the kernel module reads the timestamp 1,024 times back to
  back. It registers its hooks only if the timestamp changed at least 16 times
  – otherwise no high-resolution timer is present.

- The kernel module divides the timestamp by the #ac("GCD"). It calculates the
  #ac("GCD") from the first 100 timestamps after it is loaded or an entropy
  source is reset, and processes these timestamps undivided. A #ac("GCD") of
  1,000 or more marks the timer as too coarse: the entropy sources then credit
  no entropy.

- After the division by the #ac("GCD"), the health tests check the timestamp
  (section @sec:health-tests). The kernel module stores a timestamp that
  passes them as a 64-bit value in the per-#acs("CPU") ring of the entropy
  source. The #ac("DRBG") of the entropy source and the #ac("DRNG") of the
  #ac("ESDM") then post-process these values.

#par(first-line-indent: 0pt)[As these steps are static and never change, the
noise sources rest on the variations of the timestamps divided by the
#ac("GCD"). These variations are found in their least significant bits. The raw
entropy interfaces of the kernel module (section @sec:igdj-testing) provide the
difference of two successive timestamps of a #ac("CPU"), divided by the
#ac("GCD"), as a 64-bit value. The analysis extracts the 8 least significant
bits of this value, referred to below as “raw noise source data”. Section
@sec:kvm-measurements presents measurements of both entropy sources with the
current kernel module. The measurements of the interrupt entropy source in
sections @sec:raw-distribution to @sec:worst-regular and in appendix
@sec:measurements come from earlier versions of the kernel module, which
used the 8 least significant bits of the timestamp itself.]

=== Distribution of Raw Data <sec:raw-distribution>

A perfectly operating noise source would deliver equi-distributed raw noise
source data. Appendix @sec:measurements outlines tests on most major
#ac("CPU", pl: true). The runtime data show a common pattern of the raw noise
source data, which figure @fig:riscv illustrates. This figure uses the 1,000,000
traces of the raw noise source data from the interrupt entropy source on the
RISC-V system, which has a less-than-average entropy rate.

#figure(
  histogram("riscv"),
  caption: [Interrupt Entropy Source, RISC-V: Raw Noise Source Data
    Distribution],
) <fig:riscv>

Figure @fig:riscv shows the following characteristics:

- The histogram depicts the number of timestamps received for each of the
  256 possible timestamp values.

- The two dashed lines mark the 25% and 75% quartiles of the distribution at
  the timestamp values 63 and 192.

- The solid vertical line marks the mean of the distribution at 127.45.

- The dotted line marks the median of the distribution at 127.

- The black line marks the distribution of the timestamps.

- The figure does not depict the standard deviation of 73.89.

- The figure does not show the variation coefficient of 0.579801.

#par(first-line-indent: 0pt)[The figure and these statistical values show
that the distribution is close to an equi-distribution. Thus, even on
less-than-ideal hardware, the raw noise source data of an entropy source
instance exhibit a distribution that is close to the equi-distribution
expected of a perfectly operating noise source. As table @tab:raw-stats
shows, the quartiles, the mean and the standard deviation of all tested
systems are close to those of an equi-distribution, while the $chi^2$ test
rejects the equi-distribution for about half of them.]

A Chi-Squared Goodness-of-Fit test checks the distribution against an
equi-distribution. For the RISC-V system, it yields the following values:

- Asymptotic significance P: 0.2343

- Degrees of freedom: 255

#par(first-line-indent: 0pt)[The degrees of freedom show that the data cover
all 256 possible timing values. With an alpha of 5%, the Chi-Squared test
does not reject the hypothesis that the observed data set is
equi-distributed.]

Table @tab:raw-stats lists the statistical properties of the tested systems.

#figure({
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  show table.cell.where(x: 0): set align(left + top)
  table(
    columns: (2.3fr,) + (1fr,) * 8,
    table.header(
      [Test System], [25% Quar\u{AD}tile], [Median], [Mean],
      [75% Quar\u{AD}tile], [Std. Dev.], [Var. Coeff.], [$chi^2$ P],
      [$chi^2$ #acs("DF")],
      table.hline(stroke: 0.8pt),
    ),
    [AMD Ryzen 5950X – 64-bit #acs("KVM") environment],
      [64], [128], [127.6], [192], [73.88], [0.58], [0.0523], [255],
    [AMD EPYC Milan 7713 2 sockets 128 cores 8-way #acs("NUMA")],
      [63], [127], [127.48], [192], [73.91], [0.58], [0.4458], [255],
    [ARMv7 rev 5],
      [68], [128], [121.05], [191], [72.95], [0.60], [0], [255],
    [ARMv7 rev 5 (Freescale i.MX53)#footnote[USBArmory MK I]],
      [63], [128], [127.52], [192], [74], [0.58], [0.4693], [255],
    [ARMv7 rev 5 (Freescale i.MX6 Ultralite)#footnote[USBArmory MK II]],
      [63], [127], [127.15], [191], [73.96], [0.58], [0], [255],
    [ARM 64 bit AppliedMicro X-Gene Mustang Board],
      [63], [128], [127.54], [192], [73.94], [0.58], [0.7229], [255],
    [Intel Atom Z530 – using #acs("GUI")],
      [64], [128], [127.58], [192], [73.93], [0.58], [0.3181], [255],
    [Intel Sandy Bridge Clang Compile],
      [62], [125], [125.86], [187], [73.24], [0.58], [0.9347], [252],
    [Intel i7 8565U Whiskey Lake – 32-bit #ac("KVM") environment],
      [64], [128], [127.53], [192], [73.91], [0.58], [0.2893], [255],
    [Intel i7 8565U Whiskey Lake],
      [63], [127], [127.37], [191], [73.86], [0.58], [0], [255],
    [Intel Xeon E7 4870 8 sockets 160 #ac("CPU", pl: true) 8-way #ac("NUMA")],
      [64], [127], [127.44], [191], [73.89], [0.58], [0], [255],
    [Intel Xeon Gold 6234],
      [64], [126], [126.75], [190], [73.88], [0.58], [0],
      [127#footnote[Tested without #ac("GCD").]],
    [IBM POWER 8 LE 8286-42A],
      [63], [127], [127.66], [191], [73.86], [0.58], [0], [255],
    [IBM POWER 7 BE 8202-E4C],
      [64], [128], [130.07], [192], [73.96], [0.57], [0], [255],
    [IBM System Z z13 (machine 2964)],
      [56], [120], [118.27], [184], [73.58], [0.62], [0], [235],
    [IBM System Z z15 (machine 8561)],
      [58], [122], [124.3], [192], [73.54], [0.59], [0], [239],
    [MIPS Atheros AR7241 rev 1#footnote[Ubiquiti Nanostation M5 (xm)]],
      [64], [128], [127.55], [191], [73.88], [0.58], [0.5646], [255],
    [MIPS Lantiq 34Kc V5.6#footnote[AVM Fritz Box 7490]],
      [64], [127], [127.49], [191], [73.85], [0.58], [0], [255],
    [Qualcomm IPQ4019 ARMv7#footnote[AVM Fritz Box 7520]],
      [63], [127], [127.4], [191], [73.9], [0.58], [0], [255],
    [SiFive HiFive Unmatched RISC-V U74],
      [63], [127], [127.45], [192], [73.89], [0.58], [0.2343], [255],
  )
}
, caption: [Statistical properties of the raw noise source data of the
  tested systems]) <tab:raw-stats>

For some systems, the Chi-Squared asymptotic significance shows that an
equi-distribution is not applicable, i.e. the $chi^2$ P value is less than
0.05. Yet, the other statistical values show that the actual distribution is
neither skewed nor otherwise distorted. The distribution shows that some
timestamps have a higher likelihood than others, which hints at special
properties of the system. This observation applies to all measurements that
do not follow an equi-distribution according to the Chi-Squared
Goodness-of-Fit test. The assessment therefore takes the min-entropy estimates
given in appendix @sec:measurements to illustrate the real entropy rate.

For example, the distribution of the USB Armory Mark II system in figure
@fig:usbarmory indicates that every fourth timestamp value – those with a
remainder of 3 modulo 4 – occurs only about two-thirds as often as the rest.

#figure(
  histogram("usbarmory-mk2"),
  caption: [Interrupt Entropy Source, USB Armory Mark II: Raw Noise Source
    Data Distribution],
) <fig:usbarmory>

Another example is a specific ARMv7 system with a highly periodic timer
interrupt. Figure @fig:armv7 shows that the timestamp has a pattern. Still,
its distribution does not contradict the expectation that the noise source
delivers entropy at the rate calculated in appendix @sec:measurements. In the worst case, only the
timer interrupt causes the raw noise source data, which would then exhibit a
clear pattern. The stuck health test would identify this pattern with the
second discrete derivative and disregard the timestamp for entropy
collection.

#figure(
  histogram("armv7-timer"),
  caption: [Interrupt Entropy Source, ARMv7 with a Periodic Timer Interrupt:
    Raw Noise Source Data Distribution],
) <fig:armv7>

Figure @fig:systemz shows a similar effect on an IBM System Z z13 system.
Again, the pattern does not contradict the entropy rate calculated for this
system in appendix @sec:measurements.

#figure(
  histogram("systemz-z13"),
  caption: [Interrupt Entropy Source, IBM System Z: Raw Noise Source Data
    Distribution],
) <fig:systemz>

=== Greatest Common Divisor Assessment <sec:gcd>

The following figures and numbers show the behavior of the #ac("GCD")
application. They stem from an Intel Atom Z530 system whose #ac("GCD") is 4.

Figure @fig:without-gcd shows the distribution of the timestamp without the
#ac("GCD") application.

#figure(
  histogram("atom-without-gcd"),
  caption: [Interrupt Entropy Source, Intel Atom without #ac("GCD"): Raw
    Noise Source Data Distribution],
) <fig:without-gcd>

Figure @fig:without-gcd shows the following characteristics:

- The histogram depicts the number of timestamps received for each of the
  256 possible timestamp values.

- The two dashed lines mark the 25% and 75% quartiles of the distribution at
  the timestamp values 64 and 188.

- The solid vertical line marks the mean of the distribution at 125.99.

- The dotted line marks the median of the distribution at 124.

- The figure does not depict the standard deviation of 73.84.

- The figure does not show the variation coefficient of 0.586089.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4263

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 63

#par(first-line-indent: 0pt)[A new measurement with the #ac("GCD") applied
yields the distribution in figure @fig:with-gcd:]

#figure(
  histogram("atom-with-gcd"),
  caption: [Interrupt Entropy Source, Intel Atom with #ac("GCD"): Raw Noise
    Source Data Distribution],
) <fig:with-gcd>

Figure @fig:with-gcd shows the following characteristics:

- The histogram depicts the number of timestamps received for each of the
  256 possible timestamp values.

- The two dashed lines mark the 25% and 75% quartiles of the distribution at
  the timestamp values 64 and 192.

- The solid vertical line marks the mean of the distribution at 127.58.

- The dotted line marks the median of the distribution at 128.

- The figure does not depict the standard deviation of 73.93.

- The figure does not show the variation coefficient of 0.579468.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.3181

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[Thus, the #ac("GCD") application removes the
“unused” timestamp values without changing the overall distribution.]

=== Worst and Regular Case Distribution <sec:worst-regular>

The measurements in appendix @sec:measurements commonly apply a worst case
that triggers as many interrupts as possible in the shortest amount of time.

Two tests on the USB Armory Mark I system compare the timestamp distributions
of the worst case and of a regular case of normal system use. They yielded
the following values:

- Worst case

  - 25% quartile: 64
  - Median: 128
  - Mean: 127.6
  - 75% quartile: 192
  - Standard deviation: 73.91
  - Variation coefficient: 0.579221
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.9445
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

- Regular case

  - 25% quartile: 63
  - Median: 128
  - Mean: 127.52
  - 75% quartile: 192
  - Standard deviation: 74
  - Variation coefficient: 0.580276
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4693
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[The values indicate no statistically significant
difference. Thus, the two distributions are very similar.]

=== Measurements of the Current Kernel Module <sec:kvm-measurements>

The measurements in this section used the current kernel module in a #ac("KVM")
guest. They show what the assessment of both entropy sources yields on one
virtualized system; they provide no entropy rate for another system
(section @sec:90b-reuse).

- Host: Intel Core i7-1355U with 2 performance and 8 efficiency cores,
  Linux 7.3.5, QEMU 11.1.2 with #ac("KVM").

- Guest: Linux 7.3.4 with the hook patches, `CONFIG_HZ=1000` and
  `CONFIG_NO_HZ_FULL`, 2 vCPUs pinned to two efficiency cores of the host,
  3 GiB of memory. `random_get_entropy` reads the #ac("TSC"), which runs at
  2,611 MHz; the deltas are thus in units of 0.38 ns.

- Timestamps: the guest executes RDTSC without a #ac("VM") exit – two reads
  back to back take 34 to 36 cycles, while a CPUID, which always exits, takes
  about 2,000 cycles – and thus reads the #ac("TSC") of the host, shifted by a
  constant offset and not scaled. Of the clock sources `kvm-clock`, `tsc`,
  `hpet` and `acpi_pm`, the guest uses `tsc` (kernel command line
  `clocksource=tsc`).

- Kernel module: `BUILD_TESTING=1`, built with only the interrupt entropy
  source for the measurement of that entropy source, and with only the
  scheduler entropy source for the measurement of the latter (section
  @sec:igdj-testing).

- Load profiles: _idle_, the guest without additional load; _load_,
  `stress-ng --cpu 2 --switch 1 --io 1 --hdd 1` with its files on the
  virtual disk, i.e. #ac("CPU"), context switch and block #ac("I/O") load;
  _flood_, a ping flood of one-byte #ac("ICMP") echo requests from a neighboring
  virtual machine on the same virtual switch, the worst case of the interrupt
  entropy source; _switch_, `stress-ng --switch 2`, the worst case of the
  scheduler entropy source (section @sec:igdj-c2). The neighboring virtual
  machine and the virtual switch ran on host cores of their own.

- Collection: `esdm-getrawentropy` wrote 1,000,000 deltas to `/dev/shm`,
  with the console log level at 1 and the system journal in memory without
  kernel messages (section @sec:igdj-c1). The idle collections were limited
  in time, to 15 minutes for the interrupt and to 4 hours for the scheduler
  entropy source.

Table @tab:kvm-stats lists the statistical properties of the raw noise
source data in the form of section @sec:raw-distribution. The deltas are in
#ac("TSC") cycles of 0.38 ns. Figures @fig:kvm-kmod-irq-flood to
@fig:kvm-kmod-sched-switch show three of the distributions.

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
      [63], [127], [127.44], [191], [73.91], [0.58], [0.6311], [255],
    [Interrupt, flood],
      [64], [128], [127.51], [191], [73.89], [0.58], [0.2717], [255],
    [Scheduler, idle],
      [64], [127.5], [127.49], [192], [73.90], [0.58], [0.8353], [255],
    [Scheduler, load],
      [62], [127], [127.14], [192], [74.32], [0.58], [0], [255],
    [Scheduler, switch],
      [65], [123], [123.94], [181], [70.64], [0.57], [0], [255],
  )
}
, caption: [Statistical properties of the raw noise source data of `esdm_es`
  in a #ac("KVM") guest]) <tab:kvm-stats>

#figure(
  histogram("kvm-kmod-irq-flood"),
  caption: [Interrupt Entropy Source, #ac("KVM") Guest, Flood:
    Raw Noise Source Data Distribution],
) <fig:kvm-kmod-irq-flood>

#figure(
  histogram("kvm-kmod-sched-idle"),
  caption: [Scheduler Entropy Source, #ac("KVM") Guest, Idle:
    Raw Noise Source Data Distribution],
) <fig:kvm-kmod-sched-idle>

#figure(
  histogram("kvm-kmod-sched-switch"),
  caption: [Scheduler Entropy Source, #ac("KVM") Guest, Switch:
    Raw Noise Source Data Distribution],
) <fig:kvm-kmod-sched-switch>

#paragraph[Interrupt entropy source][The idle guest received 1.6 device
interrupts per second: its local timer raises no interrupt that the hook
observes, and without #ac("I/O") nothing else does. In 15 minutes, the
collection gathered 1,000 deltas, too few for an assessment. A guest without
#ac("I/O") thus leaves the interrupt entropy source almost without events, and
the #ac("ESDM") seeds from its other entropy sources. Under load and under the
flood, the interrupts of the virtual disk and network devices arrived 1,676 and
12,690 times per second. Their deltas – with a median of 932,374 and 92,267
cycles – vary by far more than 256 cycles, and the 8 #ac("LSB") come close to an
equi-distribution: the $chi^2$ test does not reject it.]

#paragraph[Scheduler entropy source][
The idle guest woke tasks up 26 times per second. In 4 hours, the collection
gathered 370,000 deltas, fewer than the 1,000,000 that #ac("SP") 800-90B section
3.1.3 asks for. Their median is 62,663,644 cycles, and the $chi^2$ test does
not reject the equi-distribution of the 8 #ac("LSB") (figure
@fig:kvm-kmod-sched-idle).
Under load, the median
delta between two wakeups of a #ac("CPU") is 6,062 cycles. In the switch
profile, the context switch stressor wakes tasks up so often that the deltas cluster: half of them lie
between 2,928 and 4,106 cycles. The 8 #ac("LSB") then are no longer
equi-distributed (figure @fig:kvm-kmod-sched-switch): the values around 128
occur up to 1.2 times as often as an equi-distribution implies. The min-entropy
estimates of section @sec:90b-313 account for this.]

=== Scope and Limits of the Measurements <sec:measurement-limits>

The measurements of this chapter show how the noise sources behave and that
the assessment procedure works. They are not a validation of the entropy
credited on another system, and they have these limits:

- Earlier versions: the measurements of sections @sec:raw-distribution to
  @sec:worst-regular and of appendix @sec:measurements come from earlier
  versions of the kernel module. Those versions evaluated the 8 least
  significant bits of the timestamp, the current one the difference of two
  successive timestamps divided by the #ac("GCD"). They characterize the
  noise source – the timing of interrupts – on many architectures; they do
  not assess the data the current kernel module processes, and they cover the
  interrupt entropy source only.

- One system: the measurements of the current kernel module (section
  @sec:kvm-measurements) come from one #ac("KVM") guest on one host, which
  reads the #ac("TSC") of the host without a #ac("VM") exit. They cover
  neither a system without virtualization nor another architecture, nor a
  guest whose timer is emulated, scaled or coarser.

- Missing and short data sets: the idle interrupt entropy source has no
  min-entropy estimate and no restart test, as it delivered 1,000 deltas in 15
  minutes. The idle data set of the scheduler entropy source holds 370,000
  deltas, fewer than the 1,000,000 of #ac("SP") 800-90B section 3.1.3; its
  estimate is listed, but does not meet that requirement.

#par(first-line-indent: 0pt)[An assessment for a validation therefore needs
data sets of the current kernel module from the target system, collected with
the tools of section @sec:igdj-testing, including the load profile with the
fewest events (section @sec:90b-reuse). Until then, the entropy the kernel
module credits rests on the distance between its heuristic of 1/`ESDM_ES_OSR`
bits per timestamp and the estimates measured so far, not on a measurement of
the system in use.]

== FIPS 140-3 Compliance <sec:fips1403>

#ac("FIPS", cap: true) 140-3 specifies entropy source compliance in #ac("IG")
D.J of its implementation guidance @fips1403ig. #ac("IG", cap: true) D.K
complements it with its interpretation of the #ac("SP") 800-90B requirements.
This section analyzes each requirement for compliance. Section @sec:sp80090b
analyzes the general requirement to comply with #ac("SP") 800-90B @sp80090b.

#ac("IG", cap: true) D.J continues #ac("IG") 7.18 of #ac("FIPS") 140-2
@fips1402ig under the same title, and #ac("IG") D.K continues #ac("IG") 7.19.
The additional comments 1–9 of #ac("IG") D.J carry the numbers and the
requirements of those of #ac("IG") 7.18. Comment 3 recommends the self-tests of
ISO/IEC 19790:2012 section 7.10 in place of the power-up tests of #ac("FIPS")
140-2 section 4.9.1. Comment 5 refers to #ac("IG") 9.3.A in place of #ac("IG")
7.14. The continuous random number generator test of #ac("FIPS") 140-2 #ac("IG")
9.8 has no counterpart: the health tests of #ac("SP") 800-90B section 4 take its
place.

=== FIPS 140-3 IG D.J Requirement for Statistical Testing <sec:igdj-testing>

The #ac("ESDM") provides a testing tool for raw entropy. The tests obtain the raw, unconditioned and unprocessed
noise information and record it for analysis with the #ac("SP") 800-90B
non-#ac("IID") statistical test tool. The test tool gathers raw entropy for
one execution run as well as for the restart tests required in #ac("SP")
800-90B section 3.1.4. It adjusts the data for processing by the #ac("SP")
800-90B statistical test tool, which provides the #ac("SP") 800-90B
min-entropy values.

#par(first-line-indent: 0pt)[In particular, this test covers the test
requirement of #ac("FIPS") 140-3 #ac("IG") D.J.]

The kernel module provides the raw noise source data when it is compiled with
the option `BUILD_TESTING=1` of its Makefile, for each entropy source it is
built with. For each event, the files `esdm_raw_hires` (interrupts) and
`esdm_raw_sched_hires` (task wakeups) in `/sys/kernel/debug/esdm_es` deliver
the difference of two successive timestamps of a #ac("CPU") divided by the
#ac("GCD") as a 64-bit value – undivided while the #ac("GCD") is not yet
calculated. When loaded with the module parameter `boot_raw_hires_test=1` or
`boot_raw_sched_hires_test=1`, the kernel module records the first 1,024
time deltas after it registered the hook of the entropy source, for the
restart tests. The tool `esdm-getrawentropy` reads such a file when given
its option `--debugfs-file`. The tool `esdm-extractlsb` extracts the bits for
processing by the #ac("SP") 800-90B statistical test tool. Both tools are found
in `tests/validation-helpers`, and the meson option `validation-helpers` builds
them.

With the scheduler entropy source built, every reader of these files polls
instead of sleeping: the scheduler hook runs with the run queue lock held,
where waking up a reader would deadlock. A waiting reader thus keeps one
#ac("CPU") busy, which changes the interrupts that #ac("CPU") receives. The
interrupt entropy source is therefore to be measured with a kernel module built
without the scheduler entropy source (`BUILD_ES_SCHED=0`), whose reader sleeps.

=== FIPS 140-3 IG D.J Heuristic Analysis <sec:igdj-heuristic>

#ac("FIPS", cap: true) 140-3 #ac("IG") D.J requires a heuristic analysis
compliant with #ac("SP") 800-90B section 3.2.2. Section @sec:sp80090b discusses
this #ac("SP") 800-90B requirement list.

=== FIPS 140-3 IG D.J Additional Comment 1 <sec:igdj-c1>

The first test referenced in section @sec:igdj-testing covers this
requirement.

The test collects the timestamps of the events as the kernel module receives
them. Instead of adding them to the per-#acs("CPU") ring, the kernel module
sends them to a user space application, which stores them to disk.

The same code path that would otherwise add the event data to the
per-#acs("CPU") ring invokes the collection for the raw entropy testing. Thus,
the test collects exactly the timestamps that the #ac("ESDM") would otherwise
use as noise data, and the testing does not alter the #ac("ESDM") processing.

However, the tester should store the raw entropy data obtained with the user
space tool on “disk space” that does not generate interrupts. Otherwise, the
testing itself would generate new interrupts and thus alter the measurement.
For example, a ramdisk can hold the raw entropy data while the test is
ongoing. On common Linux environments, the path `/dev/shm` is usually a
ramdisk that can readily serve as the target for the raw entropy data. If
that partition does not exist, the tester should mount a ramdisk or use a
different backing store that is guaranteed not to generate any interrupts
when writing data to it.

The raw entropy interfaces log two kernel messages for each run of up to 128
deltas. A console that prints them, such as a serial console, raises
interrupts of its own: the tester should lower the console log level during
the test (`dmesg -n 1`). The tool's progress messages to a terminal or a
network session cause interrupts as well; the tester should redirect them to
the ramdisk or discard them.

=== FIPS 140-3 IG D.J Additional Comment 2 <sec:igdj-c2>

The analysis of the lowest entropy yield gathers raw entropy data from
events that arrive at a high frequency. In this case, the timestamps are
close together, which limits their variations and thus the entropy they
provide.

In the extreme case, a neighboring system in close proximity with very little
network latency sends a flood of #ac("ICMP") echo request messages with a size
of only one byte to the system under test. Each #ac("ICMP") request triggers an
interrupt when the network card processes it. The most extreme case executes
the #ac("ESDM") in a virtual machine and lets the #ac("VMM") host, or a
neighboring virtual machine on the same virtual switch, send a ping flood to the
virtual machine, which reduces the network latency to a minimum.

For the scheduler entropy source, the counterpart is a flood of task
wakeups: processes that wake each other up in a tight loop, such as the
context switch stressor of `stress-ng --switch`. Section
@sec:kvm-measurements measures both worst cases in a virtual machine,
together with an idle and a loaded system.

The assessment assumes that the entropy does not degrade when the hardware
operates within the environmental constraints documented for the #ac("CPU"). The online health
tests are intended to detect entropy source degradation. Section
@sec:health-tests explains the actions taken on online health test failures.

=== FIPS 140-3 IG D.J Additional Comment 3 <sec:igdj-c3>

The #ac("ESDM") uses the following conditioning components:

- To collect entropy data, each entropy source of the kernel module
  concatenates its timestamps in its per-#acs("CPU") rings.

- To read the per-#acs("CPU") rings and compress the entropy data, each entropy
  source uses a #ac("DRBG") instance of its own: the timestamps are the seed of
  a reseed of the #ac("DRBG"), which then generates the output. When the kernel
  provides its SHA-3 library (`CONFIG_CRYPTO_LIB_SHA3`), which is required from
  Linux 7.2 on, the #ac("DRBG") is the XDRBG-256 over the SHAKE256 of the
  kernel. Otherwise, it is the #ac("SP") 800-90A #ac("HMAC") #ac("DRBG") with
  SHA-512 of the kernel crypto #ac("API"). Following @sp80090b section 3.1.5.1.1
  table 1, the security strength of the #ac("ESDM") is the minimum of the
  #ac("DRBG") security strength of the #ac("ESDM") and the security strength of
  256 bits of the #ac("DRBG") of the kernel module. The #ac("HMAC") #ac("DRBG")
  can be tested via #ac("ACVTS"). The kernel module verifies the XDRBG-256 with
  a known-answer test when it is loaded.

#par(first-line-indent: 0pt)[#ac("IG", cap: true) D.K resolution 7 note 1
considers a #acs("CAVP")-validated #ac("SP") 800-90A #ac("DRBG") a vetted
conditioning component. The XDRBG-256 is accepted as a vetted conditioning
component as well, as it is for the Jitter #acs("RNG") 3.7.0 – its SHAKE256 is
listed as a vetted conditioning component with a narrowest internal width of 512
bits. #ac("IG", cap: true) D.K resolution 5 sets the conditions for a
#ac("DRBG") as conditioning component, and the kernel module meets them. Before
each generate operation, it reseeds the #ac("DRBG") with timestamps carrying at
least its security strength in entropy plus the oversampling. It generates no
more than the security strength of 256 bits per reseed. It uses the #ac("DRBG")
for nothing but this conditioning.]

=== FIPS 140-3 IG D.J Additional Comment 4 <sec:igdj-c4>

The first test documented in section @sec:igdj-testing covers the restart
test.

=== FIPS 140-3 IG D.J Additional Comment 6 <sec:igdj-c6>

The entropy assessments of the tested systems (sections @sec:90b-313 and
@sec:90b-314, appendix @sec:measurements) lead to the following conclusions:

For all measurements with the raw entropy tests outlined in section
@sec:igdj-testing – of the interrupt entropy source on the systems of
appendix @sec:measurements, of both entropy sources in the #ac("KVM") guest of
section @sec:kvm-measurements – the min-entropy values are above one bit
of entropy per eight data bits. The data bits are the least significant bits
of the timestamp, or of the time delta for the current kernel module.

Under the worst-case assumption that all other bits of the time delta have no
entropy, this entropy value of more than one bit applies to one timestamp.

The kernel module continuously gathers timestamps and combines them with an
entropy-preserving #ac("DRBG"). It credits each timestamp with
1/`ESDM_ES_OSR` bits of entropy. Its Makefile sets the
oversampling rate `ESDM_ES_OSR` to a value between 1 and 25, 3 by default.
The kernel module delivers data to the #ac("DRNG") only in blocks of 256 bits
for which it gathered the necessary timestamps. For example, with the default
oversampling rate, it needs 768 timestamps for one block and delivers no
data to the #ac("DRNG") as long as it has received fewer timestamps. Effectively,
the #ac("ESDM") thus assumes one third of a bit of entropy per timestamp.

As the kernel module maintains a #ac("DRBG"), the entropy content of its output
cannot exceed the #ac("DRBG") security strength of 256 bits. The per-#acs("CPU")
rings hold the received timestamps until the #ac("ESDM") requests data – once a
ring is full, the kernel module drops newly received timestamps until the next
request takes timestamps from it.

Thus, the #ac("ESDM") data generated from the #ac("DRBG") has (close to) 1 bit
of entropy per data bit.

=== FIPS 140-3 IG D.J Additional Comment 9 <sec:igdj-c9>

N/A: the raw entropy is a non-#ac("IID") source, which the non-#ac("IID")
#ac("SP") 800-90B statistical tests process as documented in section
@sec:igdj-testing.

== SP 800-90B Compliance <sec:sp80090b>

This section analyzes the compliance of the #ac("ESDM") with #ac("SP") 800-90B
@sp80090b. It considers #ac("FIPS") 140-3 #ac("IG") D.J and #ac("IG") D.K, which
alter some of the requirements of #ac("SP") 800-90B.

=== SP 800-90B Section 3.1.1 <sec:90b-311>

The collection of raw data for the #ac("SP") 800-90B entropy testing documented
in section @sec:igdj-testing uses 1,000,000 time deltas of one entropy source
obtained in one execution round. Each of them is the difference of two
successive timestamps of a #ac("CPU"). The interface records the deltas in runs
of up to 128 consecutive events, as outlined in section @sec:90b-321-5. The
entropy source processes the events between two runs as usual and does not
record them.

The restart tests documented in section @sec:igdj-testing perform 1,000
restarts and collect the first 1,000 time deltas after each restart.

=== SP 800-90B Section 3.1.2 <sec:90b-312>

The entropy assessment of the raw entropy data including the restart tests
follows the non-#ac("IID") track.

=== SP 800-90B Section 3.1.3 <sec:90b-313>

See section @sec:igdj-c6: the assessment takes the raw noise source data to
have more than one bit of entropy per timestamp. This allows the conclusion
that one output block of the #ac("ESDM") has (close to) one bit of entropy per
data bit. Yet, the kernel module credits only one bit of entropy per
`ESDM_ES_OSR` timestamps, i.e. a third of a bit per event with the default
oversampling rate. The oversampling rate can be configured at compile time.

The first test referenced in section @sec:igdj-testing performs the following
operations to provide the #ac("SP") 800-90B min-entropy estimate:

+ Gather the raw entropy data of the timestamps.

+ Obtain the eight least significant bits of each time delta and concatenate
  them to form a bit stream.

+ Process the bit stream with the #ac("SP") 800-90B entropy testing tool to
  obtain the min-entropy estimate.

Table @tab:kvm-min-entropy lists the results of the measurements of section
@sec:kvm-measurements in bits per delta: $H_"original"$ and $H_"bitstring"$
of `ea_non_iid`, version 1.1.8, and the min-entropy
$H = min(H_"original", 8 dot H_"bitstring")$. The column Deltas/s gives the
rate of the collection, which the runs of 128 deltas limit for the scheduler
entropy source under load.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  show table.cell.where(x: 0): set align(left + top)
  table(
    columns: (1.8fr, 1.2fr) + (1fr,) * 4,
    table.header(
      [Data Set], [Deltas], [Deltas/s], [$H_"original"$],
      [$H_"bitstring"$], [$H$],
      table.hline(stroke: 0.8pt),
    ),
    [Interrupt, load],
      [1,000,000], [1,676], [7.859639], [0.899944], [7.199548],
    [Interrupt, flood],
      [1,000,000], [12,690], [7.325702], [0.898569], [7.188550],
    [Scheduler, idle],
      [370,000], [26], [7.806966], [0.894074], [7.152591],
    [Scheduler, load],
      [1,000,000], [21,097], [7.241443], [0.820361], [6.562888],
    [Scheduler, switch],
      [1,000,000], [263,158], [7.191294], [0.751895], [6.015163],
  )
}
, caption: [#ac("SP", cap: true) 800-90B min-entropy of `esdm_es` in a
#ac("KVM") guest, in bits per
  delta]) <tab:kvm-min-entropy>

All estimates lie far above the 1/3 bit per delta that the kernel module
credits with the default oversampling rate: the lowest one, 6.02 bits per
delta of the scheduler entropy source under the context switch stressor, is 18
times as high. The estimates support every oversampling rate the Makefile
allows, `ESDM_ES_OSR=1` included, which credits 1 bit per delta. The idle
interrupt collection is missing from the table: its 1,000 deltas are too few
for `ea_non_iid`. The idle collection of the scheduler entropy source holds
370,000 deltas, so its estimate carries a larger statistical uncertainty.
Appendix @sec:measurements lists the earlier measurements of the interrupt
entropy source on other systems, down to 1.93 bits per timestamp.

=== SP 800-90B Section 3.1.4 <sec:90b-314>

A restart of an entropy source is a load of the kernel module: the module
starts without a #ac("GCD"), without a preceding timestamp, with empty rings
and with the startup health test. Loaded with the module parameter
`boot_raw_hires_test=1` or `boot_raw_sched_hires_test=1` (section
@sec:igdj-testing), it records the first 1,024 time deltas after it
registered the hook of the entropy source. The first event of each #ac("CPU")
only provides the timestamp from which the following delta is calculated. The
kernel module registers the interrupt hook only once the Linux kernel #ac("RNG")
is initialized. When the kernel module is loaded at boot, a restart is a reboot,
and the recorded deltas follow the initialization of the kernel #ac("RNG").
Unloading and loading the kernel module restarts the entropy sources without
a reboot, which the measurements of section @sec:kvm-measurements used.

The test keeps the first 1,000 deltas of each of 1,000 restarts and forms the
1,000 $times$ 1,000 matrix of #ac("SP") 800-90B section 3.1.4.1: one row per
restart, holding the 8 least significant bits of each delta. The tool
`ea_restart` of the #ac("SP") 800-90B entropy assessment tool processes the
matrix:

+ It applies the sanity check of #ac("SP") 800-90B section 3.1.4.3 to the rows
  and columns.

+ It estimates the min-entropy $H_r$ of the row data set, the rows
  concatenated, and $H_c$ of the column data set, the columns concatenated,
  with the non-#ac("IID") estimators.

+ The validation test passes if $min(H_r, H_c) >= H_I \/ 2$, with the initial
  estimate $H_I$ of section @sec:90b-313. The restart test then supports
  $min(H_r, H_c, H_I)$ bits per delta.

Table @tab:kvm-restart lists the restart tests of the guest of section
@sec:kvm-measurements. Each validates the estimate $H_I$ of table
@tab:kvm-min-entropy of the same load profile.

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
      [7.199548], [7.241443], [7.295390], [passed], [passed],
    [Interrupt, flood],
      [7.188550], [6.638383], [7.224332], [passed], [passed],
    [Scheduler, idle],
      [7.152591], [7.258976], [6.638399], [passed], [passed],
    [Scheduler, load],
      [6.562888], [7.258976], [6.638383], [passed], [passed],
    [Scheduler, switch],
      [6.015163], [7.241443], [7.258976], [passed], [passed],
  )
}
, caption: [#ac("SP", cap: true) 800-90B restart tests of `esdm_es` in a
#ac("KVM") guest, in bits per
  delta]) <tab:kvm-restart>

#paragraph[Recurring values][Several values of tables @tab:kvm-min-entropy
and @tab:kvm-restart, and of the tables of chapter @sec:ebpf-assessment,
recur to the last digit in unrelated data sets: 6.638383, 6.638399,
7.241443, 7.258976 and 7.353758. The predictors and the tuple estimates of
the tool derive their result from a few integers – the length of the longest
run of correct predictions, a tuple length and its count – and the number of
samples, so that different data sets of the same size yield the same value.
6.638383 is what the MultiMCW predictor returns for 1,000,000 symbols of 8
bits whose longest run of correct predictions is 4, and 6.638399 the same for
the LZ78Y predictor. As a control, uniformly distributed random bytes of the
kernel #ac("RNG") were assessed with the same tool: of three data sets, one
yielded 6.638399 and two 6.638383 as $H_"original"$, and their restart
matrices yielded 6.638383 and 6.638399 as $H_r$ and 7.353758, a tuple
estimate, as $H_c$. These three values are thus ceilings of the estimators
for this sample size, not properties of the noise source: they bound the
entropy from below, and the estimators cannot tell a data set at such a
ceiling from an ideal one. 7.241443 and 7.258976 did not occur in the
control runs; they are taken to be values of the same kind, which the raw
data of the measurements would have to confirm.]

All restart tests passed the sanity check and the validation test. They
support $min(H_r, H_c, H_I)$ bits per delta, at least 6.02 bits for every load
profile – again far above the 1/3 bit that the kernel module credits. Loading
the kernel module wakes tasks up itself: the median delta of the restart data
of the idle scheduler entropy source is 40,791 cycles, against 62,663,644
cycles in the steady state, and the restart test validates the estimate all
the same. The idle interrupt entropy source has no restart test: at 1.6
interrupts per second, each restart would wait more than 10 minutes for its
1,024 deltas.

=== SP 800-90B Section 3.1.5 <sec:90b-315>

The conditioning component of each entropy source is its #ac("DRBG") instance in
the kernel module, as outlined in section @sec:components. The kernel module
seeds the #ac("DRBG") with the timestamps collected from the per-#acs("CPU")
rings of the entropy source, and the #ac("DRBG") then generates the output block
handed to the #ac("ESDM"). The following discussion applies to both operations
and to both entropy sources.

#paragraph[Truncation][The truncation operation ensures that the entropy in
the truncated data is at most the size of the truncated hash.]

The kernel module does not truncate the timestamps: it stores the entire
64-bit timestamp divided by the #ac("GCD"). The quantitative measurement of the
existing entropy with the #ac("SP") 800-90B tool set, however, uses the
truncated data of its least significant bits. The kernel module credits an
entropy of 1/`ESDM_ES_OSR` bits per timestamp, so the entropy present in the
data is always smaller than the data size.

The #ac("DRBG") generates at most its security strength of 256 bits per output
block. This truncation operation ensures that the truncated data contains at
most as much entropy as the generated data size. The #ac("DRBG") does not export
the remaining part of the data to any external entity but keeps it in its state
– it always uses the current #ac("DRBG") state when it generates new random
data.

#paragraph[Deviation][The entropy accounting of this truncation deviates from
#ac("SP") 800-90B section 3.1.5.1.2, which reduces the entropy of a truncated
output in proportion to the bits removed. The #ac("ESDM") does not apply this
proportional reduction. The justification is that the proportional rule and
table 1 of @sp80090b give different results for the same computation, as the
following analogy shows, and that the Output\_Entropy function of the same
section, evaluated below, supports the result of table 1. A validation has to
accept this deviation; it is listed here for that purpose.]

Assume a buffer of 512 bits of data with
256 bits of entropy. Hashing it with SHA-512 yields a message digest of 512 bits
with 256 bits of entropy. For a truncation of the digest to 256 bits, #ac("SP")
800-90B states that the entropy is 128 bits. However, #ac("SP") 800-90B section
3.1.5.1.1 table 1 states that full entropy is given to approved hash functions.
Consider SHA-512/256, which has a digest size of 256 bits and thus could
transport 256 bits of entropy following table 1. This SHA-512/256 hash operation
calculates a SHA-512 hash, with initial values of its own, truncated to 256
bits. Although the cryptographic operation of SHA-512/256 is, apart from these
initial values, identical to the #acs("ESDM")-applied truncation#footnote[With the #ac("HMAC") #ac("DRBG"), the kernel module uses a
hash of SHA-512 and fills a buffer of the #ac("DRNG") security strength size,
i.e. 256 bits.], #ac("SP") 800-90B table 1 awards 256 bits of entropy to
SHA-512/256. At the same time, #ac("SP") 800-90B would award only 128 bits to
the #acs("ESDM")-applied truncation. Because of this difference, the #ac("ESDM")
applies the entropy behavior implicitly specified in table 1, i.e. the entropy
is bounded by the available entropy and by the message digest size.
Furthermore, the Output\_Entropy formula for a vetted conditioning component of
a truncated hash yields the following calculation. It shows the entropy rate of
a SHA-512 hash that processes a buffer of 1024 bits with an assumed 384 bits of
entropy and truncates it to 256 bits. Following @sp80090b section 3.1.5.1.2, the
formula
$h_"out"^"SHA-512 trunc" = OE_"SHA-512"^"trunc" (1024, 256, 512, 384)$
is calculated as follows:

#display($P_"high" = 2^(-384)$)
#display($P_"low" = (1 - 2^(-384)) / (2^1024 - 1) approx 2^(-1024)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(1024-256) dot 2^(-1024) + 2^(-384) = 2^(-256) + 2^(-384)
  approx 2^(-256) \
  U = 2^(1024-256) + sqrt(2 dot 256 dot (2^(1024-256)) dot ln(2))
  = 2^768 + sqrt(2^777 dot ln(2)) approx 2^768 \
  omega = 2^768 times 2^(-1024) = 2^(-256) \
  underline(OE_"SHA-512"^"trunc" (1024, 256, 512, 384)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

Calculations of other entropy rates with the same formula support the
following conclusion for the truncation, as long as the input entropy is not
close to the output size (section @sec:90b-3151 gives the exact function and
the loss at the boundary):

#display($underline(OE^"trunc" (n_"in", n_"out", n w, h_"in")
  approx min(n_"in", n_"out", n w, h_"in"))$)

The #ac("ESDM") applies this function for hash truncation.

#paragraph[Concatenation][For a concatenation operation, the #ac("ESDM") adds
the entropy delivered with each data entry part.]

#paragraph[DRBG][The input size $n_"in"$ of the #ac("DRBG") is fixed, as the
#ac("DRBG") processes the timestamps collected from the per-#acs("CPU") rings
for one output block.]

The output size $n_"out"$ of the #ac("DRBG") is fixed to its security strength of 256
bits per output block – only the second block of a request for 320 or 384
bits holds 64 or 128 bits. The kernel module generates no output at all as
long as the per-#acs("CPU") rings hold too few timestamps for all blocks of a
request.

Depending on the kernel, the kernel module uses the following
#ac("DRBG", pl: true):

- Linux kernels providing the SHA-3 library (`CONFIG_CRYPTO_LIB_SHA3`), which
  Linux 7.2 and later require: XDRBG-256 with SHAKE256 and a state of 512 bits

- Older Linux kernels: #ac("SP") 800-90A #ac("HMAC") #ac("DRBG") with SHA-512
  (`drbg_nopr_hmac_sha512`), which requires the kernel patch exporting the
  #ac("DRBG") functions

#par(first-line-indent: 0pt)[The #ac("DRBG") operations specified in section
@sec:data-processing apply as follows:]

- Compression of entropy delivered from the entropy source when seeding the
  #ac("DRBG") with the timestamps collected from the per-#acs("CPU") rings.

- Generation of the output block of the entropy source from the #ac("DRBG")
  state.

#par(first-line-indent: 0pt)[The requirement of @sp80090b section 3.1.6
states that, when a vetted conditioning component combines two or more noise
sources, only one noise source is to be credited with entropy. The #ac("ESDM")
meets this requirement as follows: according to @sp80090b section 2.2, a noise
source is the phenomenon delivering entropy. Conditioning components and
health tests post-process the noise source data to form an entropy source.
Thus, the per-#acs("CPU") rings together with the #ac("DRBG") of the kernel
module form one entropy source that is compliant with #ac("SP") 800-90B.]

The #ac("DRBG") of the kernel module ensures backward secrecy when it calculates
the next round of random numbers that fill the seed buffer used to seed the
#ac("DRBG") of the #ac("ESDM") from the entropy sources: what the #ac("DRBG")
absorbed stays in its state and goes into all of its later output.

#paragraph[Approach for Calculating Entropy][The input and output sizes of the
#ac("DRBG") are fixed per output block, as the preceding paragraphs state. To
reseed a #ac("DRNG"), the noise source has to deliver
256 bits of entropy. Although the per-#acs("CPU") rings receive timestamps
continuously, a reseed requires only the entropy from
$256 dot #raw("ESDM_ES_OSR")$ timestamps – 768 timestamps by default – plus
the timestamps of the oversampling in #ac("FIPS") mode, as illustrated below.
When all per-#acs("CPU") rings have received too few timestamps to satisfy the
256-bit entropy request, the kernel module generates no output data. This
commonly happens during boot, or at runtime when too much entropy is requested.
Therefore, neither entropy source delivers seed data credited with more
entropy than its accounting attributes to the collected timestamps.]

With the #ac("DRBG") combination outlined above, the entropy calculation takes
the following approach for each data processing step outlined in section
@sec:data-processing:

- Function @eq:ep-cpu:

  - $n_"in"^"DRBG"$ equals 64 bits times the number of timestamps
    collected from the per-#acs("CPU") rings for one output block, which are
    $(256 + o) dot #raw("ESDM_ES_OSR")$ timestamps with the oversampling $o$
    of 65 bits in #ac("FIPS") mode – 129 bits for the first seed of the
    #ac("DRBG") – and of
    0 bits otherwise. With the default oversampling rate, $n_"in"^"DRBG"$
    is 49,152 bits, and 61,632 bits in #ac("FIPS") mode#footnote[With the
    default oversampling rate, the per-#acs("CPU") rings hold 4,095 timestamps
    each, and they grow with larger oversampling rates. When a different
    oversampling rate is chosen, the value needs to be adjusted accordingly.
    Yet, such a modified value has no impact on the entropy analysis.].

  - $n_"out"^"DRBG"$ is the security strength of the #ac("DRBG") of 256 bits.

  - $italic("nw")_("DRBG")$ is 512 bits: the state of the XDRBG-256 and the
    internal width of SHA-512 of the #ac("HMAC") #ac("DRBG").

- Function @eq:ep-all:

  - $n_"in"^"out"$ equals the size of the #ac("DRBG") state.

  - $n_"out"^"out"$ is the security strength of the #ac("DRBG") of 256 bits.

  - $italic("nw")_("out")$ is 512 bits like $italic("nw")_("DRBG")$.

=== SP 800-90B Section 3.1.5.1 <sec:90b-3151>

The assessment treats the #ac("DRBG") of the kernel module outlined above, which
is based on SHA-512 or SHAKE256, as a vetted conditioning component. Thus, the entropy
rate of the #ac("DRBG") output is calculated as follows with the aforementioned
variables for the #ac("DRBG"). In addition, the following considerations apply:

- The entropy content of the input $h_"in"^"DRBG"$: the input entropy of the
  #ac("DRBG") seeded with the timestamps collected from the per-#acs("CPU")
  rings equals the entropy provided by these timestamps and the entropy already
  present in the #ac("DRBG") state, as both data components are processed at the
  same time to form a new #ac("DRBG") state. The entropy held in the #ac("DRBG")
  state is never larger than its size, which complies with @sp80090b section
  3.1.5.1.1 table 1.

- The entropy content of the input $h_"in"^"out"$: the input entropy of the
  generate operation of the #ac("DRBG") equals the entropy found in the
  #ac("DRBG") state. Again, the entropy generated by the #ac("DRBG") is never
  larger than its security strength, which complies with @sp80090b section
  3.1.5.1.1 table 1.

#paragraph[Function @eq:ep-cpu Output\_Entropy][The calculation of the
Output\_Entropy of a conditioning component considers the input entropy.
Equation @eq:h-t gives the heuristic input entropy awarded for one timestamp
processed by the #ac("ESDM"). Due to the concatenation of timestamps, the
entropy of multiple timestamps can be added.]

The following two calculations illustrate the formula with numbers that are
easy to follow: a SHA-512 hash over timestamps of 8 bits, each credited with
one bit of entropy. Earlier versions of the interrupt entropy source worked
this way; the current kernel module does not hash per #ac("CPU"), and its
own parameters follow below. For this hash, the entropy after receiving 1,024 timestamps is
$h_"out"^"SHA-512" = OE_("SHA-512")(8192, 512, 512, 1024)$ following
@sp80090b section 3.1.5.1.2. Therefore, the following calculation applies:

#display($P_"high" = 2^(-1024)$)
#display($P_"low" = (1 - 2^(-1024)) / (2^8192 - 1) approx 2^(-8192)$)
#display($n = min(512, 512) = 512$)
#display($psi = 2^(8192-512) dot 2^(-8192) + 2^(-1024) = 2^(-512) + 2^(-1024)
  approx 2^(-512) \
  U = 2^(8192-512) + sqrt(2 dot 512 dot (2^(8192-512)) dot ln(2))
  = 2^7680 + sqrt(2^7690 dot ln(2)) approx 2^7680 \
  omega = 2^7680 times 2^(-8192) = 2^(-512) \
  underline(OE_("SHA-512")(8192, 512, 512, 1024)
  = -log_2(max(2^(-512), 2^(-512))) = 512)$)

As a complement, the following is the same calculation for only one received
timestamp, i.e. for the formula
$h_"out"^"SHA-512" = OE_("SHA-512")(8, 512, 512, 1)$:

#display($P_"high" = 2^(-1)$)
#display($P_"low" = (1 - 2^(-1)) / (2^8 - 1) approx 2^(-9)$)
#display($n = min(512, 512) = 512$)
#display($psi = 2^(8-512) dot 2^(-9) + 2^(-1) = 2^(-513) + 2^(-1)
  approx 2^(-1) \
  U = 2^(8-512) + sqrt(2 dot 512 dot (2^(8-512)) dot ln(2))
  = 2^(-504) + sqrt(2^(-494) dot ln(2)) approx 2^(-247) dot sqrt(ln(2))
  approx 2^(-247) \
  omega = 2^(-247) times 2^(-9) = 2^(-256) \
  underline(OE_("SHA-512")(8, 512, 512, 1)
  = -log_2(max(2^(-256), 2^(-1))) = 1)$)

Both cases lie far from the boundary $h_"in" = n_"out"$; far from it, the
following approximation holds:

#display($h_"out"^"SHA-512" = OE_("SHA-512")
  approx min(h_"in", n_"out"^"SHA-512")$)

The same calculation with a hash of 256 bits,
$OE_("SHA-256")(8192, 256, 256, 1024) = 256$ and
$OE_("SHA-256")(8, 256, 256, 1) = 1$, leads to the same approximation:

#display($h_"out"^"SHA-256" = OE_("SHA-256")
  approx min(h_"in", n_"out"^"SHA-256")$)

#paragraph[General Form and Boundary][The four examples have an input entropy
far above or far below the output size. In general, with an input much larger
than the output ($n_"in" >> n_"out"$, so that $P_"low" approx 2^(-n_"in")$ and
$U approx 2^(n_"in" - n)$) and with $n = n_"out" <= italic("nw")$, the
Output\_Entropy function of @sp80090b section 3.1.5.1.2 reduces to $psi =
2^(-n_"out") + 2^(-h_"in")$ and $omega = 2^(-n_"out")$, hence:]

$ h_"out"^"vetted" = OE_"vetted" = -log_2 (2^(-n_"out"^"vetted") + 2^(-h_"in"))
  <= min(h_"in", n_"out"^"vetted") $ <eq:vetted>

The minimum is the limit of this function for an input entropy far from the
output size, and the #ac("ESDM") uses it as its accounting rule. At the
boundary, the function stays below the minimum by the loss of table
@tab:vetted-loss: with exactly as much input entropy as output bits, one bit
is lost, and the loss halves with every further bit of input entropy. This
loss is the reason why #ac("SP") 800-90C demands 64 bits of entropy more than
the output size before it accepts the output of a vetted conditioning
component as having full entropy.

#block(breakable: false)[
#figure(
  table(columns: (auto, auto, auto, 1fr), align: left + horizon,
    table.header([$h_"in"$], [$n_"out"$], [$h_"out"$ by equation @eq:vetted],
      [Case]),
    [1], [256], [$1 - 2^(-255) \/ ln 2$], [One timestamp of the examples above],
    [256], [256], [255], [One output block outside of #ac("FIPS") mode ($o = 0$)],
    [257], [256], [255.415], [],
    [264], [256], [255.994], [],
    [321], [256], [$256 - 2^(-65) \/ ln 2$], [One output block in #ac("FIPS")
      mode ($o = 65$)],
    [385], [256], [$256 - 2^(-129) \/ ln 2$], [First output block of the
      kernel module in #ac("FIPS") mode ($o = 129$)],
  ),
  caption: [Output entropy of a vetted conditioning component near the
    boundary $h_"in" = n_"out"$],
) <tab:vetted-loss>
]

#paragraph[Consequence for the Kernel Module][Outside of #ac("FIPS") mode, the
kernel module collects no oversampling ($o = 0$), seeds its #ac("DRBG") with
timestamps credited with exactly 256 bits and credits the output block with 256
bits (equation @eq:h-hash-pools). By equation @eq:vetted, this block holds 255
bits: the accounting of the default configuration overstates the entropy of
each output block by one bit. The accounting does not compensate for this bit.
What stands against it is not credited: the entropy that earlier seeds left in
the #ac("DRBG") state, and the distance between the heuristic entropy of
1/`ESDM_ES_OSR` bits per timestamp and the measured entropy (sections
@sec:90b-313 and @sec:90b-314). A configuration that has to claim full entropy
for the output block – #ac("SP") 800-90C, #ac("FIPS") 140-3, DRG.4 – runs the
kernel module in #ac("FIPS") mode, where the oversampling of 65 bits brings the
loss down to $2^(-65) \/ ln 2$ bits.]

For the function @eq:ep-cpu as applied by the kernel module in #ac("FIPS") mode,
the same calculation with the parameters given in section @sec:90b-315 for one
output block of the #ac("DRBG") yields
$h_"out"^"DRBG" = OE_("DRBG")(61632, 256, 512, 321)$:

#display($P_"high" = 2^(-321)$)
#display($P_"low" = (1 - 2^(-321)) / (2^61632 - 1) approx 2^(-61632)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(61632-256) dot 2^(-61632) + 2^(-321) = 2^(-256)
  + 2^(-321) approx 2^(-256) \
  U = 2^(61632-256) + sqrt(2 dot 256 dot (2^(61632-256)) dot ln(2))
  = 2^61376 + sqrt(2^61385 dot ln(2)) approx 2^61376 \
  omega = 2^61376 times 2^(-61632) = 2^(-256) \
  underline(OE_("DRBG")(61632, 256, 512, 321)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

#paragraph[Function @eq:ep-all][The function @eq:ep-all uses the same
#ac("DRBG") as discussed in the preceding section. Thus, the conclusion drawn
with equation @eq:vetted applies here as well.]

#paragraph[Conclusions for Output\_Entropy][As stated in @sp80090b section
3.1.5.1.2, vetted conditioning components may claim full entropy. The
#ac("ESDM") accounts with the limit of equation @eq:vetted, which the function
reaches up to the loss of table @tab:vetted-loss:]

- $h_"out"^"SHA-512" approx min(h_"in", n_"out"^"SHA-512")$,

- $h_"out"^"SHA-256" approx min(h_"in", n_"out"^"SHA-256")$, or

- $h_"out"^"DRBG" approx min(h_"in", n_"out"^"DRBG")$ with
  $n_"out"^"DRBG" = 256$.

#par(first-line-indent: 0pt)[Based on that conclusion, the following
illustrates the entropy rate of each processing step given in section
@sec:data-processing. This entropy assessment uses $n_"out"$, the security
strength of 256 bits of the #ac("DRBG") of the kernel module.]

#paragraph[Heuristic Entropy Assessment][When a high-resolution timer is
present, the following equation defines the heuristic entropy value of the
individual timestamps – without a high-resolution timer, the kernel module
does not load, and with a timer that the #ac("GCD") shows to be too coarse, it
credits no entropy:]

$ h_t = 1 / #raw("ESDM_ES_OSR") $ <eq:h-t>

To assess whether the #ac("ESDM") heuristic entropy value is appropriate, it
must be compared with the entropy analysis results of practical measurements,
such as those outlined in sections @sec:90b-313 and @sec:90b-314. This
comparison must show that the heuristic entropy value is always lower, and thus
more conservative, than what the measurements show on target devices.

The entropy of the concatenated timestamps collected from the per-#acs("CPU")
rings of an entropy source for one output block is the sum of the entropy of
these timestamps. As the kernel module collects
$N = (256 + o) dot #raw("ESDM_ES_OSR")$ timestamps for one output block,
with the oversampling $o$ given in section @sec:90b-315, this sum is:

$ h_("CP") = sum_(n=1)^(N) (h_t)_n = 256 + o $ <eq:h-cp>

The following entropy rate applies to the seeding of the #ac("DRBG") of the
kernel module as specified by equation @eq:ep-cpu. This formula implies that the
#ac("DRBG") state holds the sum of the entropy of the timestamps it is seeded
with and the entropy remaining in the #ac("DRBG") state, capped by the security
strength of the #ac("DRBG"). The kernel module drops timestamps received while
the per-#acs("CPU") ring of their #ac("CPU") is full, so they do not contribute.

$ h_("DRBG"_n) = min(h_("CP"_n) + h_("DRBG"_(n-1)), n_"out") $ <eq:h-pool>

Similarly, the following equation applies to the entropy of the auxiliary pool
maintenance as specified by equation @eq:ap. Although this chapter does not
model this entropy source, the formula illustrates the entropy accounting of
the auxiliary pool, which is an XDRBG-256 of the #ac("ESDM"). This formula
implies that the auxiliary pool holds the sum of the entropy of the received
data, capped by the size of the #ac("XDRBG") state of 512 bits. Again, this
operation implies that the #ac("XDRBG") compresses the entropy available in the
different input data.

$ h_("aux pool") = min(h_"in"^"aux pool" + h_("aux pool"), 512) $
<eq:h-aux>

The following equation applies to the calculation of the output block of an
entropy source as specified by equation @eq:ep-all. The kernel module
credits the output block only with the entropy of the timestamps it
collected for this block less the oversampling $o$, capped by the security
strength of the #ac("DRBG"). It does not credit the entropy remaining in the
#ac("DRBG") state from earlier seeds. It generates an output block only if this
entropy is at least the security strength of the #ac("DRBG").

$ h_B = min(h_("CP"_n) - o, n_"out") $ <eq:h-hash-pools>

The entropy present in the buffer of the entropy source is, per output
block, the minimum of the entropy of the block and the bits requested from
it. A request takes at most the security strength of the #ac("DRBG") from a
block; a request for 320 or 384 bits in #ac("FIPS") mode takes a second
block for the remaining 64 or 128 bits:

$ "requested size"_s <= "security strength" = 256 $ <eq:requested>

$ h_s = min(h_B, "requested size"_s) $ <eq:h-s>

The temporary seed buffer concatenates the data of the entropy sources, so
its entropy is the sum of the entropy values credited for each entropy source
– provided the entropy sources are independent (section @sec:es-overview). $h_A$
denotes the auxiliary entropy rate, $h_E$ the #ac("IRQ") #ac("ES") entropy rate,
$h_S$ the
scheduler #ac("ES") entropy rate, $h_E^"eBPF"$ and $h_S^"eBPF"$ the entropy rates of
the #acs("eBPF")-based #ac("IRQ") and scheduler #ac("ES"), $h_J$ the Jitter
#acs("RNG") #ac("ES") entropy rate, $h_C$ the #ac("CPU") #ac("ES") entropy rate,
$h_K$ the kernel #ac("ES") entropy rate, $h_H$ that of the
#ac("HWRAND") entropy source, $h_M$ that of the #ac("TPM") 2.0 entropy source,
$h_J^"K"$ that of the kernel Jitter #acs("RNG") entropy source, and $h_X$ that
of the external entropy source:

$ h_T = h_A + h_E + h_S + h_E^"eBPF" + h_S^"eBPF" + h_J + h_C + h_K + h_H
  + h_M + h_J^"K" + h_X $ <eq:h-t-buffer>

The formulas show that the entropy is the sum of the entropy of all input
events, capped by the security strength of the #ac("DRBG") used.

When the kernel module generates the random numbers that fill the buffer of
an entropy source, it debits the entropy by taking the timestamps from
the per-#acs("CPU") rings. It takes the timestamps for an output block from the
ring of the first #ac("CPU") as far as that ring holds timestamps, and the
missing timestamps from the rings of the following #ac("CPU", pl: true).

For example, assume that the buffer of the interrupt entropy source is
filled with
$h_s = 256$ bits outside of #ac("FIPS") mode, i.e. with 768 timestamps with the
default oversampling rate. Assume further that the per-#acs("CPU") rings of 2
#ac("CPU", pl: true)
contain $N_("CPU0") = 555$ and $N_("CPU1") = 369$ timestamps. The debit
operation performs:

+ $N_("CPU0") = 555 - 555 = 0$ leaving
  $N_s^"not debited" = 768 - 555 = 213$

+ $N_("CPU1") = 369 - 213 = 156$

=== SP 800-90B Section 3.1.6 <sec:90b-316>

Each entropy source of the kernel module uses one noise source:

- The interrupt entropy source: the timing of the occurrence of interrupts.

- The scheduler entropy source: the timing of task wakeups.

#par(first-line-indent: 0pt)[The #ac("SP") 800-90B analysis covers each noise
source on its own, and the #ac("ESDM") credits at most one of the two entropy
sources (section @sec:kernel-es-overview). Thus, each entropy source
trivially meets the requirements of this section. The vetted conditioning
component of the #ac("DRBG") of the entropy source processes all data before it
is injected as seed data into the #ac("DRNG"). Thus, this operation complies
with the last paragraph of section 3.1.6.]

=== SP 800-90B Section 3.2.1 Requirement 1 <sec:90b-321-1>

This entire document is intended to provide the required analysis.

=== SP 800-90B Section 3.2.1 Requirement 2 <sec:90b-321-2>

This entire document in general, and chapter @sec:kernel-es-assessment in
particular, is intended to provide the required analysis.

=== SP 800-90B Section 3.2.1 Requirement 3 <sec:90b-321-3>

As the noise source is completely software-based, there is no specific
operating condition other than what the operating system needs to run.

The only dependency of the noise source is a high-resolution timer, which
does not change with the environmental conditions.

=== SP 800-90B Section 3.2.1 Requirement 4 <sec:90b-321-4>

This document explains the architectural security boundary.

The boundary of the implementation is the source code files provided as part
of the software delivery. This source code contains the #ac("API") calls for the
entities that use the #ac("ESDM").

=== SP 800-90B Section 3.2.1 Requirement 5 <sec:90b-321-5>

The output of the #ac("DRBG") of an entropy source, seeded with the timestamps
of its per-#acs("CPU") rings, is the output of the entropy source. The
#ac("DRBG") generates the data handed to the #ac("DRNG") on a seeding request
with the #ac("IOCTL") `ESDM_IRQ_ENT_BUF_IOCTL` or
`ESDM_SCHED_ENT_BUF_IOCTL` of
`/dev/esdm_es`.

Specific tools access the noise source output without the #ac("DRBG") operation.
These tools add interfaces that are not present, and thus not usable, when
the #ac("ESDM") is employed in production mode. These additional interfaces
gather the data for the analysis documented in section @sec:90b-313. The
collection proceeds as follows:

+ A tool switches the kernel module into raw entropy generation mode by
  reading the raw entropy interface. In this mode, the kernel module feeds each raw
  entropy event to the raw entropy collection interface and does not add it
  to the per-#acs("CPU") ring or otherwise use it.

+ When an event is received, the kernel module forwards the difference between
  its timestamp and the timestamp of the preceding event of the #ac("CPU"),
  both divided by the #ac("GCD"), to a ring buffer of 1,024 entries. The kernel
  module does not forward the first delta of a #ac("CPU") after the #ac("GCD")
  is calculated, as the preceding timestamp is still undivided.

+ The kernel module hands out the data in chunks of up to 1,024 bytes, i.e.
  128 deltas. For each chunk, it clears the ring buffer, enables the
  collection, waits until the chunk is filled and disables the collection
  again. The entropy source processes the events between two chunks – while the data is copied to the application and until it reads
  again – as usual and does not record them. The deltas therefore come in
  runs of up to 128 consecutive events, while each delta still is the
  difference of two successive timestamps of a #ac("CPU").

+ For the restart tests, the kernel module enables the collection when it is
  loaded and keeps it enabled until the ring buffer is full. The first read
  hands out the 1,024 recorded deltas.

#par(first-line-indent: 0pt)[With this approach, the tools obtain the actual
events that the #ac("ESDM") would process.]

The kernel interface is only present if the kernel module is compiled with
the option `BUILD_TESTING=1` of its Makefile, which defines
`CONFIG_ESDM_RAW_HIRES_ENTROPY` and `CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY`
for the entropy sources built. This option should not be set in
production kernel modules. In addition, the kernel module neither creates the
interface nor hands out data while the kernel is in lockdown mode.

=== SP 800-90B Section 3.2.1 Requirement 6 <sec:90b-321-6>

See section @sec:igdj-c1 for details on how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP 800-90B Section 3.2.1 Requirement 7 <sec:90b-321-7>

See section @sec:90b-314 for a description of the restart test.

=== SP 800-90B Section 3.2.2 Requirement 1 <sec:90b-322-1>

This entire document provides the complete discussion of the noise source.

=== SP 800-90B Section 3.2.2 Requirement 2 <sec:90b-322-2>

The interrupt noise source is based on the receipt of interrupts, which
follows the usage of the system. The more #ac("I/O") the system performs, the
more interrupts the #ac("ESDM") receives. The scheduler noise source follows the
activity of the processes: a task is woken up when the #ac("I/O") it waits for
completes, when its sleep expires or when another task signals it. The
entropy rate is only a function of these events and the timer. It does not depend on any other system property such
as physical characteristics (e.g. temperature variations or voltage/current
variations). This finding is consistent with the fact that the noise source
is a purely software-based noise source that relies on the presence of a
high-resolution timer. The timer used is a cycle counter that increments at
a given rate.

=== SP 800-90B Section 3.2.2 Requirement 3 <sec:90b-322-3>

See section @sec:90b-3151 for a discussion of the entropy provided by the
noise sources.

This document provides no stochastic model.

=== SP 800-90B Section 3.2.2 Requirement 4 <sec:90b-322-4>

The noise source is expected to execute in the kernel address space. Thus,
the memory separation of the operating system keeps unprivileged processes
from reading the state of the kernel module; an adversary with kernel
privileges is outside the scope of this assessment.

=== SP 800-90B Section 3.2.2 Requirement 5 <sec:90b-322-5>

The output of the noise sources is non-#ac("IID"), as it rests on the time
deltas of events, which may depend on preceding events.

=== SP 800-90B Section 3.2.2 Requirement 6 <sec:90b-322-6>

The noise source generates the data via the #ac("DRBG") generate function as
outlined in section @sec:90b-315.

The #ac("DRBG") generates fixed-length output blocks of 256 bits. Instead of
output blocks with less entropy, it generates no data, as outlined in section
@sec:90b-3151.

=== SP 800-90B Section 3.2.2 Requirement 7 <sec:90b-322-7>

N/A, as each entropy source implements one noise source. The two noise
sources observe related events, so the #ac("ESDM") credits at most one of the
two entropy sources (section @sec:kernel-es-overview).

However, the #ac("ESDM") employs other, completely self-contained entropy
sources, each of which may be compliant with #ac("SP") 800-90B. To seed its
#ac("DRNG"), the #ac("ESDM") concatenates the output of all entropy sources
compliant with #ac("SP") 800-90C, as outlined in section @sec:sp80090c.

=== SP 800-90B Section 3.2.3 Requirement 1 <sec:90b-323-1>

The conditioning component is the #ac("DRBG") of the kernel module. See section
@sec:90b-315 for a discussion of the input and output sizes.

=== SP 800-90B Section 3.2.3 Requirement 2 <sec:90b-323-2>

The #ac("HMAC") #ac("DRBG") of the kernel crypto #ac("API") used for the
conditioning component is #acs("ACVP")-testable. The kernel module verifies the
XDRBG-256 with its known-answer test when it is loaded. It compiles the
XDRBG-256 implementation of the #ac("ESDM"), which the #ac("ESDM") test suite
verifies against the known answer of its reference implementation.

=== SP 800-90B Section 3.2.3 Requirement 3 <sec:90b-323-3>

For the defined #ac("DRBG", pl: true), no key is required: their state is
derived from the seed data only.

=== SP 800-90B Section 3.2.3 Requirement 4 <sec:90b-323-4>

For the defined #ac("DRBG", pl: true), no key is required: their state is
derived from the seed data only.

=== SP 800-90B Section 3.2.3 Requirement 5 <sec:90b-323-5>

The conditioning component is the #ac("DRBG") of the kernel module. See section
@sec:90b-3151 for a discussion of the narrowest internal width and the output
block size.

=== SP 800-90B Section 3.2.4 Requirement 1 <sec:90b-324-1>

The #ac("ESDM") source code provides test tools for measuring raw entropy in
`tests/validation-helpers`. Anyone can use these tools without further
knowledge of the #ac("ESDM").

=== SP 800-90B Section 3.2.4 Requirement 2 <sec:90b-324-2>

Section @sec:90b-313 discusses the operation of the test tools for gathering
raw data. This explanation shows that the tools obtain the raw unconditioned
data.

=== SP 800-90B Section 3.2.4 Requirement 3 <sec:90b-324-3>

The provided tools for gathering raw entropy include the exact steps for
performing the tests. These steps require no knowledge of the noise source.

=== SP 800-90B Section 3.2.4 Requirement 4 <sec:90b-324-4>

The raw entropy tools can be executed in the same environment that hosts the
#ac("ESDM"). Thus, the data is generated under normal operating conditions.

=== SP 800-90B Section 3.2.4 Requirement 5 <sec:90b-324-5>

The raw entropy tools can be executed in the same environment that hosts the
#ac("ESDM"). Thus, the data is generated on the same hardware and operating
system that executes the #ac("ESDM").

=== SP 800-90B Section 3.2.4 Requirement 6 <sec:90b-324-6>

The test tools are publicly available with the #ac("ESDM") source code (appendix
@sec:source-code), which allows the replication of any raw entropy
measurements.

=== SP 800-90B Section 3.2.4 Requirement 7 <sec:90b-324-7>

See section @sec:igdj-c1 for details on how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP 800-90B Section 4.3 Requirement 1 <sec:90b-43-1>

The implemented health tests comply with #ac("SP") 800-90B section 4.4 as
described in section @sec:90b-44.

=== SP 800-90B Section 4.3 Requirement 2 <sec:90b-43-2>

When either health test fails, the kernel module:

- Emits a failure log,

- Resets the noise source by discarding the timestamps collected in the
  per-#acs("CPU") rings, and

- Restarts the #ac("SP") 800-90B startup health tests.

#par(first-line-indent: 0pt)[Until the startup health test completes again,
the entropy source delivers no data to the #ac("ESDM").]

Both health tests apply two cut-off values: reaching the cut-off value for
the significance level of $alpha = 2^(-30)$ triggers the reset described
above. The kernel module treats reaching the cut-off value for the
significance level of $alpha = 2^(-60)$ as a permanent failure. In addition,
such a failure restarts the counting of both health tests and causes a kernel
panic if the kernel module is loaded with the module parameter
`esdm_panic_on_permanent_health_failure=1`.

=== SP 800-90B Section 4.3 Requirement 3 <sec:90b-43-3>

The health tests apply the following false positive probability rates:

- #ac("RCT", cap: true): The false positive rate is $alpha = 2^(-30)$ and
  therefore complies with the recommended false positive probability.

- #ac("APT", cap: true): The cut-off value is 459, compliant with #ac("SP")
  800-90B section 4.4.2 for non-binary data at a significance level of
  $alpha = 2^(-30)$, where one timestamp is assumed to provide at least
  1/`ESDM_ES_OSR` bit of entropy, i.e. H = 1/3 with the default oversampling
  rate – the cut-off value is 325 for H = 1#footnote[The Excel function
  CRITBINOM, which #ac("SP") 800-90B section 4.4.2 references, seems to be
  imprecise when calculating the value. The data was obtained with R-Project
  using the formula
  $2 + "qbinom"(1 - 2^(-30), 511,
    2^(-1 \/ class("normal", #raw("ESDM_ES_OSR"))))$, which
  accounts for the first sample of the window being the base value. A
  SageMath script calculates the cut-off values for $alpha = 2^(-60)$.].

=== SP 800-90B Section 4.3 Requirement 4 <sec:90b-43-4>

The kernel module applies a startup health test to 1,024 noise source
samples. In addition, it checks for a high-resolution timer when it is loaded
and credits no entropy if the #ac("GCD") of the first 100 timestamps shows the
timer to be too coarse (section @sec:noise-source). If the startup test
succeeds, the kernel module reuses the collected noise source samples to
generate random numbers.

=== SP 800-90B Section 4.3 Requirement 5 <sec:90b-43-5>

The noise sources support on-demand testing in the sense that the caller may
restart the kernel or unload and load the kernel module.

=== SP 800-90B Section 4.3 Requirement 6 <sec:90b-43-6>

The health tests check the raw, unconditioned timestamp data directly
obtained from the noise source, before the timestamps are injected into the
per-#acs("CPU") ring and further processed with the #ac("DRBG") conditioning
component.

=== SP 800-90B Section 4.3 Requirement 7 <sec:90b-43-7>

Section @sec:health-tests documents the health tests.

When the kernel is booted in #ac("FIPS") mode with the kernel command line
option `fips=1`, the tests execute as follows:

- During startup, the kernel module applies the #ac("RCT") and the #ac("APT") to
  1,024 samples. The caller can trigger the startup test again by rebooting the
  kernel or by loading the kernel module again.

- At runtime, the kernel module applies the #ac("RCT") to each received timestamp. The #ac("APT") collects 512 timestamps and is calculated over all of
  them. If the test fails, the kernel module resets the entropy source to drop
  all existing entropy – the timestamps collected in the per-#acs("CPU") rings
  – and performs the startup testing again.

=== SP 800-90B Section 4.3 Requirement 8 <sec:90b-43-8>

No noise source failure modes are currently known or suspected.

=== SP 800-90B Section 4.3 Requirement 9 <sec:90b-43-9>

N/A, as the noise source is pure software. The software is expected to
execute on hardware operating within its defined nominal operating
conditions.

=== SP 800-90B Section 4.4 <sec:90b-44>

The health tests described in section @sec:health-tests cover the
requirements of the #ac("SP") 800-90B health tests.

The #ac("SP") 800-90B compliant health tests are implemented with the following
rationale:

/ RCT: The Repetition Count Test implemented by the #ac("ESDM") compares two
  back-to-back timestamps to verify that they are not identical. If the
  number of identical back-to-back timestamps reaches the cut-off value of
  $30 dot #raw("ESDM_ES_OSR")$, i.e. 90 with the default oversampling rate,
  the #ac("RCT") raises a failure, which is reported and causes a reset of the
  entropy source. The #ac("RCT") uses a cut-off value based on the following:
  $alpha = 2^(-30)$, within the range $2^(-40) <= alpha <= 2^(-20)$ that
  #ac("SP") 800-90B section 4.3 requirement 3 recommends, stated as the $alpha$
  that the cut-off values are calculated with, following #ac("FIPS") 140-3
  #ac("IG") D.K resolution 15. In addition, one timestamp is assumed to provide
  at least 1/`ESDM_ES_OSR` bit of entropy, i.e. $H = 1 \/ 3$ with the
  default oversampling rate. Applying these values to the formula given in
  #ac("SP") 800-90B section 4.4.1 yields the cut-off value of
  $1 + 30 dot #raw("ESDM_ES_OSR")$, i.e. 91 identical values. The kernel
  module counts the repetitions after the first value, so its cut-off of 90
  repetitions corresponds to these 91 values. The permanent failure applies
  the cut-off value calculated with $alpha = 2^(-60)$, i.e.
  $60 dot #raw("ESDM_ES_OSR")$ identical back-to-back timestamps.

  When the #ac("RCT") passes, the counter is set to zero for the next time delta
  to arrive. In mathematical terms, verifying that back-to-back values are not
  identical means calculating the first discrete derivative of the timestamp
  and showing that it is not zero. In addition, the #ac("ESDM") enhances the
  #ac("RCT"): it also calculates the second and third discrete derivatives of
  the timestamp to be concatenated with the per-#acs("CPU") ring. With that,
  the #ac("RCT") assesses up to 4 consecutive timestamp values. The #ac("RCT")
  passes only if all derivatives are non-zero. If one discrete derivative shows
  a zero, the #ac("RCT") counter is increased. Thus, the second and third
  derivatives make the #ac("RCT") even more conservative. The assessment
  considers the first discrete derivative to be identical to the “approved”
  #ac("RCT") specified in #ac("SP") 800-90B section 4.4. In addition, the second discrete
  derivative identifies linear patterns, and the third identifies quadratic
  patterns. As the additional pattern recognition does not invalidate the
  mandatory pattern recognition, the assessment considers this #ac("RCT")
  approach an enhanced version of the “approved” #ac("RCT"). Thus, it meets requirement (a)
  of #ac("SP") 800-90B section 4.5.

/ APT: The #ac("ESDM") implements the Adaptive Proportion Test as defined in
  #ac("SP") 800-90B section 4.4.2. As explained in other parts of the document,
  one timestamp value is assumed to have (at least) 1/`ESDM_ES_OSR`
  bit of entropy. Thus, with the default oversampling rate, the cut-off value
  for the #ac("APT") is 459 (325 for one bit of entropy per timestamp),
  compliant with #ac("SP") 800-90B section 4.4.2 for non-binary data with a
  significance level of $alpha = 2^(-30)$. The permanent failure applies the
  cut-off value of 479 for $alpha = 2^(-60)$. The cut-off values are
  tabulated for oversampling rates of 1 to 15
  (`kernel/shared/esdm_health_cutoffs.h`); a higher rate uses the values of
  15, where the cut-off equals the window size of 512, so that the #ac("APT")
  then only fails on a window of identical values. The #ac("APT") uses the four least
  significant bits of the timestamp. During initialization, the #ac("APT") sets
  a timestamp as the base and compares all subsequent timestamps to it. If
  both values are identical, the #ac("APT") increases its counter by one. The
  window size of the #ac("APT") is 512 timestamps. The implementation therefore
  provides an “approved” #ac("APT").

== NIST Clarification Requests <sec:nist>

Beyond the requirements of #ac("FIPS") 140-3 and #ac("SP") 800-90B, #ac("NIST")
requests clarification of the following questions.

=== Sensitivity of the Timing Measurements <sec:nist-sensitivity>

The question is whether the logic that measures the timing of interrupts
and task wakeups is sensitive enough to capture the variances of that
timing.

Sensitivity means that the logic captures and measures timing variations.
The stuck test, applied to each timestamp of both entropy sources, enforces
this: it accepts a timestamp only if the first, second and third discrete
derivatives of the timestamp are non-zero. Therefore, the timestamps of
the received and processed events vary, so the #ac("ESDM") health test ensures
that the timestamp mechanism is sufficiently sensitive.

=== Dependency Between the Timing Measurements <sec:nist-dependency>

#ac("NIST", cap: true) also asks for a rationale why there are no dependencies
between individual timing measurements.

Explicit or implicit human actions create the interrupts this argument rests
on, such as those of input, network and storage devices. The #ac("ESDM")
measures the timestamp of the occurrence of these interrupts. Thus, the
#ac("ESDM") measures the effects of operations triggered by human interventions.
Timer interrupts occur as well, without human action. The timestamp has a high
resolution in the nanosecond range.

The #ac("ESDM") does not claim that the timing measurements are free of
dependencies, and its entropy claim does not need them to be. Dependencies
exist: a periodic timer produces interrupts at nearly constant distances, a
device delivers its interrupts in bursts, and the code path from the event to
the reading of the timestamp is the same for every event. The assessment
accounts for them in three ways:

- The noise source is assessed as a non-#ac("IID") source (section
  @sec:90b-313): the estimators of the non-#ac("IID") track – among them the
  Markov, the compression, the t-tuple and the longest repeated substring
  estimates and the predictors – measure the entropy of a sample given the
  samples before it, and the lowest of them is the result. A dependency
  between successive timestamps lowers this result; it is not assumed away.

- The entropy credited is a fraction of that result: 1/`ESDM_ES_OSR` bits –
  a third of a bit by default – per timestamp, against the measured rates of
  sections @sec:90b-313 and @sec:90b-314. The dependencies that matter are
  thus those of the few least significant bits of a timestamp of nanosecond
  resolution, which vary with the latency of the interrupt delivery even for
  a strictly periodic event.

- At runtime, the stuck test rejects timestamps whose first, second or third
  discrete derivative is zero, i.e. the linear and quadratic patterns of a
  periodic event at the resolution of the timer, and in #ac("FIPS") mode the
  #ac("RCT") and the #ac("APT") detect a source that degrades into
  repetitions.

#par(first-line-indent: 0pt)[What remains unaddressed is a dependency that
the estimators do not see within the 1,000,000 samples of a data set, e.g. a
pattern with a longer period. The restart tests (section @sec:90b-314) bound
it across boots.]

The same argument applies to the task wakeups of the scheduler entropy
source: the completion of #ac("I/O"), expiring timers and other tasks wake tasks
up, driven by the same activity. A timer-driven wakeup recurs periodically, but
its timestamp varies in the least significant bits with the latency of the
timer interrupt and of the scheduler. Between the two entropy sources, a
dependency exists, as an interrupt may wake up a task: the #ac("ESDM") therefore
credits at most one of them (section @sec:kernel-es-overview).

== SP 800-90B Compliant Configuration <sec:90b-config>

To use the #ac("ESDM") in an #ac("SP") 800-90B compliant way, the integrator
must apply the following configuration settings. These settings cover
requirements for the compile-time options found in the #ac("ESDM") meson
configuration framework.

The following compile-time settings must be observed:

- `fips140` must be enabled.

- `es_irq` or `es_sched` must be enabled for the entropy source to be
  credited, to which the entropy discussion of this chapter applies.

- The oversampling rate `ESDM_ES_OSR` in the Makefile of the kernel
  module must be set such that the resulting rate of 1/`ESDM_ES_OSR` bits of
  entropy per timestamp does not exceed the rate resulting from the entropy
  assessment outlined in section @sec:90b-reuse.

- The entropy rate of the credited entropy source must be greater than zero:
  it caps the entropy rate of the kernel module. For the interrupt entropy
  source, the default of `es_irq_entropy_rate=256` leaves the rate of the
  kernel module unchanged. Crediting the scheduler entropy source requires
  `es_sched_entropy_rate=256` and `es_irq_entropy_rate=0`, as only one of
  them may be credited.

- The #ac("ESDM") Linux kernel module must be enabled and compiled as documented
  in `kernel/esdm_es/README.md`, which also lists the kernel patches to apply.
  The Makefile in this directory must have the credited entropy source
  enabled: `BUILD_ES_IRQ=1` (the default) or `BUILD_ES_SCHED=1` (not the
  default).

One requirement applies to the runtime configuration. The kernel must be booted with the kernel command line option `fips=1` to
enable the #ac("SP") 800-90B health test.

#par(first-line-indent: 0pt)[To verify #ac("SP") 800-90B compliance, the file
`/proc/sys/kernel/random/esdm_type` or the `esdm_rpcc_status` #ac("RPC")
#ac("API") call provides a status indicator: the state of the credited entropy
source reports #ac("SP") 800-90B compliance once the startup health test of the
kernel module has completed.]

For a configuration compliant with #ac("SP") 800-90A and #ac("SP") 800-90B, the
following requirements must be met:

- All requirements for #ac("SP") 800-90B documented in section @sec:90b-config
  must be met.

- The #ac("ESDM") compile-time option `drng_hash_drbg`, which provides the
  #ac("SP") 800-90A #ac("DRBG") of the builtin crypto backend, must be enabled,
  or another crypto backend with an #ac("SP") 800-90A #ac("DRBG") must be
  selected.

#par(first-line-indent: 0pt)[Section @sec:health-tests lists the output
interfaces covered by the health tests. Table @tab:path-classes lists
the classes of #ac("SP") 800-90C and #ac("AIS") 20/31 that every interface
meets.]

== Reuse of SP 800-90B Analysis <sec:90b-reuse>

To reuse the #ac("SP") 800-90B analysis of this document, the integrator must
perform the following steps on the target platform:

+ Obtain raw noise source data of the credited entropy source through its raw
  noise source interface on the intended target platform as explained in
  section @sec:90b-313. Process the obtained data with the #ac("SP") 800-90B
  tool to obtain an entropy rate. This rate must be above the entropy rate per
  time delta configured with the oversampling rate `ESDM_ES_OSR` of the
  kernel module, i.e. above 1/`ESDM_ES_OSR`. For example, the tools of
  `tests/validation-helpers` obtain and assess 1,000,000 time deltas of the
  interrupt entropy source as follows; for the scheduler entropy source, the
  file `esdm_raw_sched_hires` takes the place of `esdm_raw_hires`:

  ```sh
  esdm-getrawentropy -f /sys/kernel/debug/esdm_es/esdm_raw_hires \
                     -s 1000000 -o /dev/shm/data.out 2>/dev/null
  esdm-extractlsb /dev/shm/data.out data.bin 1000000 FF
  ea_non_iid data.bin 8
  ```

  For the interrupt entropy source, use a kernel module built without the
  scheduler entropy source (section @sec:igdj-testing).

+ Obtain the restart data through the raw noise source interface on the
  intended target platform as explained in section @sec:90b-314, for example
  for the interrupt entropy source:

  ```sh
  for i in $(seq -w 1 1000); do
    insmod esdm_es.ko boot_raw_hires_test=1
    p=/sys/module/esdm_es/parameters/boot_raw_hires_test
    while [ "$(cat $p)" != 2 ]; do sleep 0.2; done
    dd if=/sys/kernel/debug/esdm_es/esdm_raw_hires of=/dev/shm/$i.bin \
       bs=8192 count=1 status=none
    rmmod esdm_es
  done
  ```

  Form the matrix of the first 1,000 deltas of each restart and process it
  with `ea_restart` to verify:

  + the sanity test applied to the restart data must pass, and

  + the minimum of the row-wise and column-wise entropy rates must not be
    less than half of the entropy rate from measurement (1), and the entropy
    assessment of the noise source based on the restart data must be at least
    the entropy rate per timestamp mentioned in (1).

#par(first-line-indent: 0pt)[If these steps succeed, the integrator satisfies all
#ac("SP") 800-90B criteria and does not need to prepare their own #ac("SP")
800-90B analysis, since this document covers all other aspects of the #ac("SP")
800-90B analysis.]

The #ac("ESDM") library code distribution provides the measurement and
validation tools in `tests/validation-helpers`. The meson option
`validation-helpers` builds them.
