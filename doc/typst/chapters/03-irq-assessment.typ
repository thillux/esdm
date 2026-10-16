#import "../template.typ": *
#import "../plots/histogram.typ": histogram

// Unnumbered display equation (LaTeX equation*/displaymath).
#let display(body) = math.equation(block: true, numbering: none, body)
// "Output_Entropy" as used throughout the SP800-90B calculations.
#let OE = math.italic("Output_Entropy")

= Interrupt Entropy Source Assessment <sec:irq-assessment>

This section documents the entropy assessment and the compliance with various
standards of the interrupt entropy source. All other entropy sources are
treated as black boxes by the ESDM and must therefore deliver their own
entropy assessment.

The interrupt entropy source assessed here is the one implemented by the Linux
kernel module `esdm_es.ko` of addon/linux\_esdm\_es: hook patches for the
supported kernel versions call the module for every interrupt, the module
collects and health tests the time stamps and conditions them with an
SP800-90A DRBG, and the ESDM reads the result through the ioctls of the device
file /dev/esdm\_es (section @sec:irq-processing). The eBPF-based interrupt
entropy source (`es_irq_ebpf`, section @sec:ebpf) observes the same noise
source - the timing of interrupts - on a stock kernel, but processes it
differently: it is not covered by the analysis of this chapter and is
uncredited by default (`es_irq_ebpf_entropy_rate` is 0) until its entropy rate
is determined for the deployment environment with the measurement tooling of
addon/es\_ebpf\_testing.

The entropy sources of the auxiliary pool, the Jitter RNG and the CPU-based
entropy source are all not related to the interrupt entropy source. Thus, the
combination of all those entropy sources is subject to the SP800-90C
assessment provided in section @sec:sp80090c.

== Noise Source Behavior <sec:noise-source>

The noise source component of an entropy source contains the
non-deterministic, entropy-producing activity. For the interrupt entropy
source this is the timing of the arrival of interrupts. The general behavior
of the noise source can be characterized by analyzing the time stamps of the
arrival time. Before performing this analysis, a recap of the noise source is
important:

- When an interrupt occurs, the kernel module obtains a high-resolution time
  stamp with `random_get_entropy`. Technically it may be a cycle counter
  offered by the CPU that produces the time stamp which is unrelated to time,
  but provides a fast-moving counter. When it is loaded, the module reads the
  time stamp 1,024 times back to back and registers the interrupt entropy
  source only if it changed at least 16 times - otherwise no high-resolution
  timer is present (`esdm_highres_timer_detect`).

- The time stamp is divided by the greatest common divisor (GCD) that is
  calculated from the first 100 time stamps. A GCD of 1,000 or more marks the
  timer as too coarse: the source then credits no entropy
  (`esdm_gcd_add_value`).

- The GCD-divided time stamp is health tested (section @sec:health-tests). A
  time stamp passing the tests is stored as a 64 bit value in the per-CPU
  event ring of the module (`esdm_es_ring_add`). These values are subject to
  post-processing by the DRBG of the module and, after they were delivered to
  the ESDM, by the DRNG of the ESDM.

#par(first-line-indent: 0pt)[Considering these static and never-changing
steps, the noise source rests on the variations of the GCD-divided time
stamps, which are concentrated in their least significant bits. The
measurements presented in the following sections and in appendix
@sec:measurements were obtained with earlier versions of the interrupt entropy
source, which recorded the 8 least significant bits of the GCD-divided time
stamp. They are kept as the characterization of the noise source. These 8 bits
are subsequently referenced as “raw noise source data”. The raw entropy
interface of the current kernel module (section @sec:ig718-testing) records
the difference of two successive GCD-divided time stamps of a CPU as a 64 bit
value, of which `esdm-extractlsb` extracts the least significant bits for the
SP800-90B tool.]

=== Distribution of Raw Data <sec:raw-distribution>

If the noise source would operate perfectly, an equi-distribution of the raw
noise source data is to be expected. Various tests have been conducted on most
major CPUs as outlined in appendix @sec:measurements. Using the runtime data,
a common pattern of the raw noise source data emerges that can be seen with
figure @fig:riscv. This figure uses the 1,000,000 traces of the raw noise
source data from the IRQ entropy source on the RISC-V, i.e. a system with
less-then-average entropy rate.

#figure(
  histogram("riscv"),
  caption: [RISC-V Raw Noise Source Data Distribution],
) <fig:riscv>

Figure @fig:riscv shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 63 and 192, respectively

- The mean of the distribution is marked with the red line which is 127.45.

- The median of the distribution is marked with the blue line at 128.

- The black line marks the distribution of the time stamps.

- The standard derivation is not depicted, but it is at 73.89.

- The variation coefficient is not shown in the figure, but it is 0.579801.

#par(first-line-indent: 0pt)[The figure together with the mentioned
statistical values clearly shows that it is close to an equi-distribution.
This means that the raw noise source data for an entropy source instance on a
less-than-ideal hardware still exhibit a distribution that is close to the
expected entropy source for a perfect operation. The distributions of most
tested systems are always close to an equi-distribution as shown with the
table below.]

To verify that the distribution is an equi-distribution, a Chi-Squared
Goodness-of-Fit test is applied. For the mentioned RISC-V system, the
following values are observed:

- Asymptotic significance P: 0.2343

- Degrees of freedom: 255

#par(first-line-indent: 0pt)[The degrees of freedom shows that indeed all 256
possible timing values are covered. Applying an alpha of 5%, the Chi-Squared
test indicates that the observed data set is an equi-distribution.]

With the table below, the statistical properties for the different tested
systems are listed.

#{
  set text(size: 10pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  table(
    // As wide as in the original, which extends into the right margin.
    columns: (83pt,) + (41pt,) * 8,
    table.header(
      [Test System], [25% Quar\u{AD}tile], [Median], [Mean],
      [75% Quar\u{AD}tile], [Std. Deriv.], [Var. Coeff.], [$chi^2$ P],
      [$chi^2$ DF],
      table.hline(stroke: 1.5pt),
    ),
    [AMD Ryzen 5950X - 64-bit KVM environment],
      [64], [128], [127.6], [192], [73.88], [0.58], [0.0523], [255],
    [AMD EPYC Milan 7713 2 sockets 128 cores 8-way NUMA],
      [63], [127], [127.48], [192], [73.91], [0.58], [0.4458], [255],
    [ARMv7 rev 5],
      [68], [128], [121.05], [191], [72.95], [0.60], [0], [255],
    [ARMv7 rev 5 (Freescale i.MX53)#footnote[USBArmory MK I]],
      [63], [128], [127.52], [192], [74], [0.58], [0.4693], [255],
    [ARMv7 rev 5 (Freescale i.MX6 Ultralite)#footnote[USBArmory MK II]],
      [63], [127], [127.15], [191], [73.96], [0.58], [0], [255],
    [ARM 64 bit AppliedMicro X-Gene Mustang Board],
      [63], [128], [127.54], [192], [73.94], [0.58], [0.7229], [255],
    [Intel Atom Z530 – using GUI],
      [64], [128], [127.58], [192], [73.93], [0.58], [0.3181], [255],
    [Intel Sandy Bridge Clang Compile],
      [62], [125], [125.86], [187], [73.24], [0.58], [0.9347], [252],
    [Intel i7 8565U Whiskey Lake – 32-bit KVM environment],
      [64], [128], [127.53], [192], [73.91], [0.58], [0.2893], [255],
    [Intel i7 8565U Whiskey Lake],
      [63], [127], [127.37], [191], [73.86], [0.58], [0], [255],
    [Intel Xeon E7 4870 8 sockets 160 CPUs 8-way NUMA],
      [64], [127], [127.44], [191], [73.89], [0.58], [0], [255],
    [Intel Xeon Gold 6234],
      [64], [126], [126.75], [190], [73.88], [0.58], [0],
      [127#footnote[Tested without GCD.]],
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

The Chi-Squared asymptotic significance shows for some systems that an
equi-distribution is not applicable, i.e. when the $chi^2$ P value is less
than 0.05. Yet, when considering the other statistical values, the actual
distribution is neither skewed nor otherwise loop-sided. When looking at the
distribution, it becomes evident that some time stamps have a higher
likelihood than others which hint to special properties of the system. This
observation applies to all measurements which do not follow an
equi-distribution based on the Chi-Squared Goodness-of-Fit test. This allows
the conclusion that the min-entropy estimates given in appendix
@sec:measurements can be considered to illustrate the real entropy rate.

For example, the distribution for the USB Armory Mark II system shown with
figure @fig:usbarmory indicates that all time stamp values divisible by 8 are
only chosen two-thirds as often as the rest.

#figure(
  histogram("usbarmory-mk2"),
  caption: [USB Armory Mark II: Raw Noise Source Data],
) <fig:usbarmory>

Another example is a specific ARMv7 system which contains a very periodic
timer interrupt. Figure @fig:armv7 shows that the time stamp has a pattern but
still exhibits a distribution that does not contradict the expectation to
deliver entropy at the rate calculated in appendix @sec:measurements. In the
worst case that the timer interrupt only causes the raw noise source data
which would exhibit a clear pattern, the stuck health test would identify this
pattern with the second discrete derivative and disregards time stamp for
entropy collection.

#figure(
  histogram("armv7-timer"),
  caption: [Periodic timer interrupt: Specific ARMv7 System Raw Noise Source
    Data],
) <fig:armv7>

A similar effect is visible on an IBM System Z z13 system shown with figure
@fig:systemz. Again, the shown pattern does not contradict the entropy rate
calculated for this system in appendix @sec:measurements.

#figure(
  histogram("systemz-z13"),
  caption: [IBM System Z Raw Noise Source Data],
) <fig:systemz>

=== Greatest Common Divisor Assessment <sec:gcd>

The behavior of the GCD application can be clearly seen with the following
figures and numbers obtained for an Intel Atom Z530 system whose GCD is 4.

Without the application of the GCD, the distribution of the time stamp is
given with figure @fig:without-gcd

#figure(
  histogram("atom-without-gcd"),
  caption: [Without GCD - Raw Noise Source Data Distribution],
) <fig:without-gcd>

Figure @fig:without-gcd shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 63 and 188, respectively

- The mean of the distribution is marked with the red line which is 125.99.

- The median of the distribution is marked with the blue line at 128.

- The standard derivation is not depicted, but it is at 73.84.

- The variation coefficient is not shown in the figure, but it is 0.586089.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4263

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 63

#par(first-line-indent: 0pt)[When applying the GCD, and obtaining a new
measurement, the distribution shown with figure @fig:with-gcd emerges:]

#figure(
  histogram("atom-with-gcd"),
  caption: [With GCD - Raw Noise Source Data Distribution],
) <fig:with-gcd>

Figure @fig:with-gcd shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 64 and 192, respectively

- The mean of the distribution is marked with the red line which is 127.58.

- The median of the distribution is marked with the blue line at 124.

- The standard derivation is not depicted, but it is at 73.93.

- The variation coefficient is not shown in the figure, but it is 0.579468.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.3181

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[This shows that the application of the GCD
removes the “unused” time stamp values without changing the overall
distribution.]

=== Worst and Regular Case Distribution <sec:worst-regular>

The measurements shown in appendix @sec:measurements commonly are obtained by
applying a worst-case which triggers as much interrupts as possible in the
shortest amount of time.

To compare the distributions of the time stamp between the worst case and a
regular case of normal system use, the USB Armory mark I system was tested
twice with the following result values:

- Worst case

  - 25% quartile: 64
  - Median: 128
  - Mean: 127.6
  - 75% quartile: 192
  - Standard derivation: 73.91
  - Variation coefficient: 0.579221
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.9445
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

- Regular case

  - 25% quartile: 63
  - Median: 128
  - Mean: 127.52
  - 75% quartile: 192
  - Standard derivation: 74
  - Variation coefficient: 0.580276
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4693
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[The values indicate no statistical significant
difference allowing the conclusion that both distributions are very
similar.]

== FIPS 140-2 Compliance <sec:fips1402>

FIPS 140-2 specifies entropy source compliance in FIPS 140-2 IG 7.18. This
section analyzes each requirement for compliance. The general requirement to
comply with SP800-90B @sp80090b is analyzed in section @sec:sp80090b.

=== FIPS 140-2 IG 7.18 Requirement For Statistical Testing <sec:ig718-testing>

The ESDM is provided with the following testing tools:

- Raw Entropy Tests: The kernel module built with `BUILD_TESTING=1` in its
  Makefile provides the debugfs file
  `/sys/kernel/debug/esdm_es/esdm_raw_hires` that delivers the raw
  unconditioned and unprocessed noise information (section
  @sec:test-interfaces). The tool `esdm-getrawentropy` (built with the meson
  option `validation-helpers`, man page `esdm-getrawentropy(8)`) records it
  for one execution run, `esdm-extractlsb` extracts the least significant bits
  of each sample, and the SP800-90B non-IID statistical test tool of NIST
  (`ea_non_iid`) provides the SP800-90B minimum entropy values. With the
  module parameter `boot_raw_hires_test=1`, the module records the first
  1,024 events after it is loaded, which provides the data for the restart
  tests required in SP800-90B section 3.1.4.

#par(first-line-indent: 0pt)[In particular the first test covers the test
requirement of FIPS 140-2 IG 7.18.]

=== FIPS 140-2 IG 7.18 Heuristic Analysis <sec:ig718-heuristic>

FIPS 140-2 IG 7.18 requires a heuristic analysis compliant to SP800-90B
section 3.2.2. The discussion of this SP800-90B requirement list is given in
section @sec:sp80090b.

=== FIPS 140-2 IG 7.18 Additional Comment 1 <sec:ig718-c1>

The first test referenced in section @sec:ig718-testing covers this
requirement.

The test collects the time stamps of interrupts as they are received by the
kernel module. While the collection is active, the recorded events are not
processed by the module to add them to its event ring, they are sent to a user
space application for storing them to disk.

The collection of the interrupt data for the raw entropy testing is invoked
from the same code path that would otherwise add it to the event ring
(`esdm_time_process_common`): the GCD-divided time stamp is taken the same
way, and the difference to the previous time stamp of the CPU is recorded.
Thus, the test collects the data that would otherwise have been used by the
ESDM as noise data. Thus, the testing does not alter the ESDM processing.

However, the tester performing the test should observe the following caveat:
the raw entropy data obtained with the user space tool should be stored on
“disk space” that will not generate interrupts as otherwise the testing would
itself generate new interrupts and thus alter the measurement. For example, a
ramdisk can be used to store the raw entropy data while the test is ongoing.
On common Linux environments, the path `/dev/shm` is usually a ramdisk that
can readily be used as a target for storing the raw entropy data. If that
partition is non-existent, the tester should mount a ramdisk or use different
backing store that is guaranteed to not generate any interrupts when writing
data to it.

=== FIPS 140-2 IG 7.18 Additional Comment 2 <sec:ig718-c2>

The lowest entropy yield is analyzed by gathering raw entropy data received
from interrupts that come in high frequency. In this case, the time stamps
would be close together where the variations and thus the entropy provided
with these time stamps would be limited.

The extreme case would be to send a flood of ICMP echo request messages with a
size of only one byte to the system under test from a neighboring system that
has a close proximity with very little network latency. Each ICMP request
would trigger an interrupt as it is processed by the network card. The most
extreme case can be achieved when executing the ESDM in a virtual machine
where the VMM host sends a ping flood to the virtual machine. In this case,
network latency would be reduced to a minimum. In the subsequent sections,
test results are shown which are generated with an ESDM executing in a virtual
machine where the host sends a flood of ICMP echo request messages to trigger
a worst case measurement.

The entropy is not considered to degrade when using the hardware within the
environmental constraints documented for the used CPU. The online health tests
are intended to detect entropy source degradation. In case of online health
test failures, section @sec:health-tests explains the applied actions.

=== FIPS 140-2 IG 7.18 Additional Comment 3 <sec:ig718-c3>

The kernel module uses the following conditioning component:

- The collected time stamps are post-processed with an SP800-90A DRBG of the
  kernel module: the HMAC_DRBG with SHA-512 by default, alternatively the
  Hash_DRBG with SHA-512 or the CTR_DRBG with AES-256 as selected with the
  module parameter `esdm_drbg_type` on kernels up to Linux 7.1; from Linux 7.2
  on, the module carries its own HMAC_DRBG with SHA-512
  (esdm\_drbg\_kcapi.c). The time stamps are the seed of a DRBG reseed, after
  which the DRBG generates one output block of its security strength of 256
  bits (`esdm_es_drbg_pool_extract_block`).

- The security strength of the data delivered by the interrupt entropy source
  is limited to the security strength of that DRBG, 256 bits
  (`esdm_security_strength` of the kernel module).

=== FIPS 140-2 IG 7.18 Additional Comment 4 <sec:ig718-c4>

The restart test is covered by the first test documented in section
@sec:ig718-testing.

=== FIPS 140-2 IG 7.18 Additional Comment 6 <sec:ig718-c6>

The entropy assessment usually shows this conclusion – tests performed on
Intel x86-based systems show the following conclusions:

The entropy rate for all devices validated with the raw entropy tests
outlined in section @sec:ig718-testing show that the minimum entropy values
are always above one bit of entropy per four data bits. The data bits are the
least significant bits of the time stamp generated by the raw noise.

Assuming the worst case that all other bits in the time delta have no
entropy, that entropy value above one bit of entropy applies to one time
stamp.

The kernel module credits less: with the oversampling rate `ESDM_ES_OSR` of
the module (3 by default, set in its Makefile), $R = 256 dot
#raw("ESDM_ES_OSR")$ time stamps are required for 256 bits of entropy
(`CONFIG_ESDM_IRQ_ENTROPY_RATE`), i.e. one time stamp is credited with
$1 \/ #raw("ESDM_ES_OSR")$ bit of entropy. The ESDM can lower the credit
further with its option `es_irq_entropy_rate`, but never raise it above the
rate the module was loaded with (`esdm_irq_set_entropy_rate`).

The per-CPU event ring holds at most 4,095 time stamps for the default
oversampling rate (4,096 slots, more only as a higher oversampling rate
requires). When a ring is full, new time stamps are dropped until the ESDM
extracts data from it (`esdm_es_ring_add`). Every extraction of a 256 bit
block takes the number of time stamps that are credited with 256 bits plus
the oversampling of the conditioning, and a block is only produced when that
number of time stamps is available. Each block delivered to the ESDM is
credited with one bit of entropy per data bit.

=== FIPS 140-2 IG 7.18 Additional Comment 9 <sec:ig718-c9>

N/A as the raw entropy is a non-IID source and processed with the non-IID
SP800-90B statistical tests as documented in section @sec:ig718-testing.

== SP800-90B Compliance <sec:sp80090b>

This chapter analyzes the compliance of the ESDM to the SP800-90B @sp80090b
standard considering the FIPS 140-2 implementation guidance 7.18 which alters
some of the requirements mandated by SP800-90B.

=== SP800-90B Section 3.1.1 <sec:90b-311>

The collection of raw data for the SP800-90B entropy testing documented in
section @sec:ig718-testing uses 1,000,000 consecutive time stamps obtained in
one execution round.

The restart tests documented in section @sec:ig718-testing perform 1,000
restarts collecting 1,000 consecutive time stamps.

=== SP800-90B Section 3.1.2 <sec:90b-312>

The entropy assessment of the raw entropy data including the restart tests
follows the non-IID track.

=== SP800-90B Section 3.1.3 <sec:90b-313>

Please see section @sec:ig718-c6: The entropy of the raw noise source data is
believed to have more than one bit of entropy per time stamp, whereas the
kernel module credits $1 \/ #raw("ESDM_ES_OSR")$ bit per time stamp. The
credited rate can be lowered further at compile time of the module and of the
ESDM.

The first test referenced in section @sec:ig718-testing performs the following
operations to provide the SP800-90B minimum entropy estimate:

+ Gathering of the raw entropy data of the time stamps with
  `esdm-getrawentropy`.

+ Obtaining the least significant bits of each sample with `esdm-extractlsb`
  - the four least significant bits for the results below - and concatenate
  them to form a bit stream.

+ The bit stream is processed with the SP800-90B entropy testing tool to
  gather the minimum entropy.

#par(first-line-indent: 0pt)[For example, on an Intel Core i7 Skylake system
executing the ESDM in a KVM guest, the SP800-90B tool shows the following
minimum entropy values when multiplying the SP800-90B tool bit-wise minimum
entropy by four since four bits are processed: 3.452064.]

=== SP800-90B Section 3.1.4 <sec:90b-314>

For the restart tests, the raw entropy data is collected for the first 1,000
interrupt events received by the ESDM after a restart of the noise source: the
module parameter `boot_raw_hires_test=1` records the first 1,024 events after
the kernel module is loaded, which, with the module loaded during boot,
implies a reboot of the operating system for one collection of raw entropy.
This implies that for gathering the 1,000 restart samples, the test system is
rebooted 1,000 times.

Each restart test round stores its time stamps in an individual file.

After all raw entropy data is gathered, a matrix is generated where each line
in the matrix lists the time stamp of one restart test round. The first column
of the matrix, for example, therefore contains the first time stamp for each
boot cycle of the Linux kernel with the ESDM.

The SP800-90B minimum entropy values column and row-wise is calculated the
same way as outlined above:

+ Gathering of the raw restart entropy data of the time stamps.

+ Obtaining the four least significant bits of each time stamp either
  row-wise or column-wise and concatenate them to form a bit stream. There are
  1,000 bit streams row-wise, and 1,000 bit streams column-wise boundary
  generated.

+ The bit streams are processed with the SP800-90B entropy testing tool to
  gather the minimum entropy.

#par(first-line-indent: 0pt)[In a following step, the sanity check outlined
in SP800-90B section 3.1.4.3 is applied to the restart test results. The steps
given in 3.1.4.3 are applied.]

For example, on an Intel Core i7 Skylake system executing the ESDM in a KVM
guest, the SP800-90B tool shows the following minimum entropy values when
multiplying the SP800-90B tool bit-wise minimum entropy by four since eight
bits are processed:

- Using the 8 least significant bits of the time stamps in column-wise
  assessment – lowest entropy value of all 1,000 column entries: 3.455504

- Using the 8 least significant bits of the time stamps in row-wise
  assessment – lowest entropy value of all 1,000 column entries: 3.393808

- Sanity check of the 1,000 x 1,000 matrix passes with value of one

#par(first-line-indent: 0pt)[With the shown values, the restart test
validation passes according to SP800-90B section 3.1.4.]

=== SP800-90B Section 3.1.5 <sec:90b-315>

The conditioning component applied to the interrupt entropy source is the
SP800-90A DRBG of the kernel module outlined in section @sec:ig718-c3. Each
output block of 256 bits is generated as follows
(`esdm_es_drbg_pool_extract_block`):

+ Collection: the time stamps stored in the per-CPU event rings are taken
  CPU by CPU until the number required for the block is reached. With $R$
  time stamps per 256 bits of entropy and the oversampling $o$, this is
  $ceil((256 + o) dot R \/ 256)$ time stamps of 64 bits each. In FIPS mode
  (kernel booted with `fips=1`), $o$ is 64 + 1 bits, and 128 + 1 bits for the
  first block after the DRBG was allocated (`esdm_compress_osr`,
  `esdm_init_osr`) - the additional bit reaches full entropy in the internal
  state after the HMAC update, as the code notes. Without FIPS mode, $o$ is
  zero.

+ Conditioning: the collected time stamps are the seed of a reseed of the DRBG
  (the DRBG update function of SP800-90A), followed by one generate operation
  of 256 bits with the string “ESDM\_IRQ\_DRBG” as additional input. The DRBG
  was instantiated with that string as personalization string.

+ Crediting: the block is credited with 256 bits of entropy only if the
  collected time stamps carry at least $256 + o$ bits; otherwise no output is
  produced and the time stamps stay in the ring.

#par(first-line-indent: 0pt)[The ESDM requests 256 bits, $256 + 64$ bits or,
for the initial seeding with oversampling, $256 + 128$ bits from the interrupt
entropy source (`ESDM_IRQ_CONF`); a request of more than 256 bits takes two
blocks.]

#paragraph[Truncation][No truncation is applied: the DRBG generates exactly
the requested number of bits of each block, at most its security strength.]

#paragraph[Concatenation][When applying a concatenation operation, the ESDM
simply adds the entropy delivered with each data entry part. The time stamps
are concatenated as seed of the DRBG, and the blocks of a request of more than
256 bits are concatenated in the output buffer.]

#paragraph[DRBG][The input of the conditioning $n_"in"$ is the number of
collected time stamps times 64 bits. The output $n_"out"$ is one DRBG output
block of 256 bits. The narrowest internal width $n w$ is the size of the
internal state of the DRBG, 512 bits for the HMAC_DRBG with SHA-512.]

SP800-90B section 3.1.5.1.2 defines the output entropy of a conditioning
component. Applying it to one block with the default values - $R = 768$
($#raw("ESDM_ES_OSR") = 3$) and $o = 65$ - the block is generated from
$ceil(321 dot 768 \/ 256) = 963$ time stamps, i.e. $n_"in" = 963 dot 64 =
61632$ bits carrying $h_"in" = 321$ bits of entropy, and
$h_("out"_"DRBG") = OE_"DRBG"(61632, 256, 512, 321)$ is calculated:

#display($P_"high" = 2^(-321)$)
#display($P_"low" = (1 - 2^(-321)) / (2^61632 - 1) approx 2^(-61632)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(61632-256) dot 2^(-61632) + 2^(-321) = 2^(-256) + 2^(-321)
  approx 2^(-256) \
  U = 2^(61632-256) + sqrt(2 dot 256 dot (2^(61632-256)) dot ln(2))
  = 2^61376 + sqrt(2^61385 dot ln(2)) approx 2^61376 \
  omega = 2^61376 times 2^(-61632) = 2^(-256) \
  underline(OE_"DRBG"(61632, 256, 512, 321)
  = -log_2(max(2^(-256) + 2^(-321), 2^(-256))) approx 256)$)

The calculation can be generalized with the following formula, which
underlies the data entropy management of the conditioning applied by the
ESDM:

$ h_("out") = OE = min(h_"in", n_"out", n w) $ <eq:vetted>

#paragraph[Approach for Calculating Entropy][In order to reseed a DRNG, 256
bits of entropy are to be generated from the noise source. Although the
per-CPU event rings receive interrupt time stamps continuously, only the time
stamps of one request are consumed by it. Only when the rings hold too few
time stamps to satisfy the request, no output data is generated
(`esdm_es_drbg_pool_extract`). This commonly happens during boot or at runtime
when too much entropy is requested. The ESDM does not consider itself fully
seeded before it received the entropy required for that (section
@sec:seed-levels).]

=== SP800-90B Section 3.1.5.1 <sec:90b-3151>

The heuristic entropy value for the individual time stamps is defined with
the following equation applicable when a high-resolution timer is present –
the absence of a high-resolution timer makes the kernel module not register
the interrupt entropy source:

$ h_t = 256 / R = 1 / #raw("ESDM_ES_OSR") $ <eq:h-t>

Note, in order to assess whether the heuristic entropy value is appropriate,
it must be compared with the entropy analysis result received from practical
measurements such as outlined in sections @sec:90b-313 and @sec:90b-314. This
comparison must show that the heuristic entropy value is always lower and
thus more conservative than what the measurements show on target devices.

The additional input of the DRBG generate operation, the string
“ESDM\_IRQ\_DRBG”, is credited with no entropy:

$ h_"addtl" = 0 $ <eq:h-a>

The entropy held in the event ring of one CPU is the sum of the entropy of
the time stamps stored in it, limited by the capacity of the ring of 4,095
time stamps for the default oversampling rate:

$ h_("ring") = min(n_"events", 4095) dot h_t $ <eq:h-cp>

The entropy available from the interrupt entropy source is the sum over the
rings of all online CPUs, from which the oversampling is deducted twice in
FIPS mode (`esdm_es_drbg_avail_entropy`); it is zero until the SP800-90B
startup test completed:

$ h_("avail") = sum_(c=0)^("max CPU") h_("ring"_c) - 2 o $ <eq:h-hash-pools>

For one output block, the DRBG is seeded with the time stamps of the
following entropy:

$ h_"in" = ceil((256 + o) dot R / 256) dot h_t >= 256 + o $ <eq:h-pool-cc>

Following equation @eq:vetted, the entropy of one output block, after the
deduction of the oversampling, is:

$ h_"block" = min(h_"in" - o, 256) = 256 $ <eq:h-pool>

The requested size is the size of the seed buffer slot of the interrupt
entropy source, which is the security strength of the DRNG, plus the
oversampling of 64 or, for the initial seeding, 128 bits when oversampling is
enabled:

$ "requested size"_s in {256, 256 + 64, 256 + 128} $ <eq:requested>

The request is served completely or not at all: with $b$ the number of blocks
it takes,

$ h_s = cases("requested size"_s & "if" h_"avail" >= b dot (256 + o),
  0 & "otherwise") $ <eq:h-s>

Similarly, the following equation applies to the entropy of the auxiliary
pool maintenance as specified by equation @eq:ap. Note, although this entropy
source is not considered to be modeled in this chapter, the formula is still
provided. This formula implies that the auxiliary pool holds the sum of the
entropy of the received data capped by the size of the state of its
XDRBG-256, 512 bits (`esdm_get_digestsize`, section @sec:aux-pool):

$ h_("aux pool") = min(h_("in"_("aux pool")) + h_("aux pool"), 512) $
<eq:h-aux>

The entropy of the temporary seed buffer following equation @eq:t is simply
an addition of the entropy values credited for each of the entropy sources
delivering data to it, $h_s$ of this chapter being the one of the interrupt
entropy source:

$ h_T = sum_("ES") h_"ES" $ <eq:h-t-buffer>

When the ESDM obtains data from the interrupt entropy source, the time stamps
that were collected for the delivered blocks are removed from the rings by
advancing the read pointers of the rings (`esdm_es_ring_release`). The other
entropy sources maintain their own entropy estimates independently.

=== SP800-90B Section 3.1.6 <sec:90b-316>

The ESDM uses the following noise sources for the interrupt entropy source:

- The noise source of the timing of the occurrence of interrupts. The entire
  SP800-90B analysis covers this one noise source. Thus, the requirements in
  this section for the interrupt noise source are trivially met.

#par(first-line-indent: 0pt)[The only other data processed by the conditioning
component is the additional input of the DRBG, which is credited with zero
bits of entropy (equation @eq:h-a). All data is processed by the conditioning
component before it is injected as seed data into the DRNG.]

=== SP800-90B Section 3.2.1 Requirement 1 <sec:90b-321-1>

This entire document is intended to provide the required analysis.

=== SP800-90B Section 3.2.1 Requirement 2 <sec:90b-321-2>

This entire document in general and chapter @sec:irq-assessment in particular
is intended to provide the required analysis.

=== SP800-90B Section 3.2.1 Requirement 3 <sec:90b-321-3>

There is no specific operating condition other than what is needed for the
operating system to run since the noise source is a complete software-based
noise source.

The only dependency the noise source has is a high-resolution timer which
does not change depending on the environmental conditions.

=== SP800-90B Section 3.2.1 Requirement 4 <sec:90b-321-4>

This document explains the architectural security boundary.

The boundary of the implementation is the source code files provided as part
of the software delivery: the kernel module of addon/linux\_esdm\_es with its
kernel patches, and the ESDM reading it through the ioctls of /dev/esdm\_es.
These ioctls are only available to a caller that opened the device file with
the capability `CAP_SYS_ADMIN` (`esdm_cdev_open`).

=== SP800-90B Section 3.2.1 Requirement 5 <sec:90b-321-5>

The output of the interrupt noise source is the output of the DRBG of the
kernel module, generated from the per-CPU event rings. I.e. the event rings
hold the data that is given to the DRBG when the ESDM requests seeding.

The noise source output without the conditioning is accessed with specific
tools which add interfaces that are not present and thus not usable when
employing the kernel module in production mode. These additional interfaces
are used for gathering the data used for the analysis documented in section
@sec:90b-313. These interfaces perform the following operation:

+ Switch the kernel module into raw entropy generation mode by reading the
  debugfs file (or, for the first 1,024 events after loading, with the module
  parameter `boot_raw_hires_test=1`). This implies that each raw entropy event
  is fed to the raw entropy collection interface and not stored in the event
  ring or otherwise used.

+ When an interrupt event is received, forward the difference of its time
  stamp to the previous one of the CPU to a ring buffer of 1,024 entries. This
  operation is performed repeatedly until the ring buffer is full or the user
  space application read that ring buffer.

+ When an application requests the reading of the ring buffer, the data is
  extracted from the kernel and the ring buffer is cleared.

#par(first-line-indent: 0pt)[With this approach, the actual interrupt events
which would be processed by the kernel module are obtained.]

The kernel interface is only present if the kernel module is compiled with
`BUILD_TESTING=1`, which defines CONFIG\_ESDM\_RAW\_HIRES\_ENTROPY. This
option should not be set in production kernel modules. In addition, the module
neither creates the debugfs files nor records data when the kernel is in
lockdown mode.

=== SP800-90B Section 3.2.1 Requirement 6 <sec:90b-321-6>

Please see section @sec:ig718-c1 for details how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP800-90B Section 3.2.1 Requirement 7 <sec:90b-321-7>

See section @sec:90b-314 for a description of the restart test.

=== SP800-90B Section 3.2.2 Requirement 1 <sec:90b-322-1>

This entire document provides the complete discussion of the noise source.

=== SP800-90B Section 3.2.2 Requirement 2 <sec:90b-322-2>

The noise source is based on the receipt of interrupts. The receipt of
interrupts follows the usage of the system. The more I/O is performed with the
system, the more interrupts are received by the ESDM. The entropy rate only is
a function of the received I/O events and the timer and does not depend on any
other system property such as physical characteristics (e.g. temperature
variations or voltage/current variations). This finding is consistent with the
fact that the noise source is a pure software-based noise source which relies
on the presence of a high-resolution timer. Note, the used timer is a cycle
counter that increments with a given rate.

=== SP800-90B Section 3.2.2 Requirement 3 <sec:90b-322-3>

See sections @sec:90b-3151 for a discussion of the entropy provided by the
interrupt noise source.

A stochastic model is not provided.

=== SP800-90B Section 3.2.2 Requirement 4 <sec:90b-322-4>

The noise source is expected to execute in the kernel address space. This
implies that the operating system process isolation and memory separation
guarantees that adversaries cannot gain knowledge about the ESDM operation.

=== SP800-90B Section 3.2.2 Requirement 5 <sec:90b-322-5>

The output of the noise source is non-IID as it rests on the execution time of
a fixed set of CPU operations and instructions.

=== SP800-90B Section 3.2.2 Requirement 6 <sec:90b-322-6>

The noise source generates the data via the DRBG of the kernel module as
outlined in section @sec:90b-315.

The DRBG generates fixed-length blocks of 256 bits. A block is only generated
when the event rings hold sufficient entropy for it as outlined in section
@sec:90b-3151.

=== SP800-90B Section 3.2.2 Requirement 7 <sec:90b-322-7>

N/A as no additional noise source is implemented with the interrupt entropy
source.

Though, the ESDM employs complete self-contained other entropy sources which
may be compliant to SP800-90B by itself. To seed the DRNG maintained by the
ESDM, the output of all entropy sources are concatenated compliant to
SP800-90C as outlined in section @sec:sp80090c.

=== SP800-90B Section 3.2.3 Requirement 1 <sec:90b-323-1>

The conditioning component is the SP800-90A DRBG of the kernel module. See
section @sec:90b-315 for a discussion of the input and output sizes.

=== SP800-90B Section 3.2.3 Requirement 2 <sec:90b-323-2>

On kernels up to Linux 7.1, the conditioning uses the DRBG implementation of
the Linux kernel crypto API, whose functions the kernel patch
0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM exports. From Linux
7.2 on, the kernel module carries an HMAC_DRBG with SHA-512 built on the
HMAC-SHA512 library of the kernel; a known-answer test with the NIST ACVP
vector the kernel used for its `drbg_nopr_hmac_sha512` guards that
implementation (esdm\_drbg\_kcapi.c).

=== SP800-90B Section 3.2.3 Requirement 3 <sec:90b-323-3>

The DRBG is instantiated with the personalization string “ESDM\_IRQ\_DRBG”
only; its key is derived from the seed data and is never set from outside.

=== SP800-90B Section 3.2.3 Requirement 4 <sec:90b-323-4>

See section @sec:90b-323-3: no key is supplied to the conditioning component.

=== SP800-90B Section 3.2.3 Requirement 5 <sec:90b-323-5>

The conditioning component is the SP800-90A DRBG. See section @sec:90b-315
for a discussion of the narrowest internal width and the output block size.

=== SP800-90B Section 3.2.4 Requirement 1 <sec:90b-324-1>

Test tools for measuring raw entropy are provided with the ESDM source code:
`esdm-getrawentropy` and `esdm-extractlsb` in addon/test, and the kernel
module testing support in addon/linux\_esdm\_es. These tools can be used by
everybody without further knowledge of the ESDM.

=== SP800-90B Section 3.2.4 Requirement 2 <sec:90b-324-2>

The operation of the test tools for gathering raw data are discussed in
section @sec:90b-313. This explanation shows that the raw unconditioned data
is obtained.

=== SP800-90B Section 3.2.4 Requirement 3 <sec:90b-324-3>

The provided tools for gathering raw entropy contains exact steps how to
perform the tests (addon/test/README.md and the man pages
`esdm-getrawentropy(8)` and `esdm-extractlsb(8)`). These steps do not require
any knowledge of the noise source.

=== SP800-90B Section 3.2.4 Requirement 4 <sec:90b-324-4>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated under normal operating conditions.

=== SP800-90B Section 3.2.4 Requirement 5 <sec:90b-324-5>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated on the same hardware and operating system
that executes the ESDM.

=== SP800-90B Section 3.2.4 Requirement 6 <sec:90b-324-6>

The test tools are publicly available with the ESDM source code (appendix
@sec:source-code) allowing the replication of any raw entropy measurements.

=== SP800-90B Section 3.2.4 Requirement 7 <sec:90b-324-7>

Please see section @sec:ig718-c1 for details how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP800-90B Section 4.3 Requirement 1 <sec:90b-43-1>

The implemented health tests comply with SP800-90B sections 4.4 as described
in section @sec:90b-44.

=== SP800-90B Section 4.3 Requirement 2 <sec:90b-43-2>

When either health test fails, the kernel module:

- Emits a failure log,

- Resets the noise source - the time stamps in the event rings are discarded
  and the GCD is calculated anew (`esdm_irq_reset`) -, and

- Restarts the SP800-90B startup health tests.

#par(first-line-indent: 0pt)[This implies that no data is produced by the
interrupt entropy source until the startup health tests completed again.]

A failure exceeding the permanent cutoff values of section @sec:90b-44 is a
permanent failure: it causes a kernel panic if the module was loaded with the
module parameter `esdm_panic_on_permanent_health_failure=1`, and the reset
outlined above otherwise.

=== SP800-90B Section 4.3 Requirement 3 <sec:90b-43-3>

The following false positive probability rates are applied:

- RCT: The false positive rate is $alpha = 2^(-30)$ for the intermittent
  cutoff and $alpha = 2^(-60)$ for the permanent cutoff, and therefore
  complies with the recommended false positive probability.

- APT: The cutoff values are calculated for non-binary data at significance
  levels of $alpha = 2^(-30)$ (intermittent) and $alpha = 2^(-60)$
  (permanent) with the time stamp assumed to provide $1 \/ #raw("ESDM_ES_OSR")$
  bit of entropy, i.e. $H = 1 \/ #raw("ESDM_ES_OSR")$#footnote[The code notes
  the cutoff formula in the syntax of R as
  $C = 2 + "qbinom"(1 - 2^(-30), 511, 2^(-1\/"osr"))$, following SP800-90B
  comment \#10b of the referenced UL comments; for $alpha < 2^(-53)$ the
  values were calculated with SageMath (esdm\_health.h).].

=== SP800-90B Section 4.3 Requirement 4 <sec:90b-43-4>

The kernel module applies a startup health test of 1,024 noise source samples
- two windows of the APT. The collected noise source samples are re-used for
the generation of random numbers if the startup test was successful.

=== SP800-90B Section 4.3 Requirement 5 <sec:90b-43-5>

The noise source supports on-demand testing in the sense that the caller may
restart the kernel.

=== SP800-90B Section 4.3 Requirement 6 <sec:90b-43-6>

The health tests are applied to the raw, unconditioned time stamp data
directly obtained from the noise source before they are stored in the
per-CPU event ring and further processed with the DRBG conditioning
component.

=== SP800-90B Section 4.3 Requirement 7 <sec:90b-43-7>

The health tests are documented with section @sec:health-tests.

The tests are executed as follows:

- During startup, the RCT and the APT are applied to 1,024 samples. The
  startup test is performed again after every health test failure and when
  the caller reboots the kernel.

- At runtime, the RCT is applied to each received time stamp. The APT
  collects 512 time stamps. The APT is calculated over all 512 time stamps.
  If a test fails, the interrupt entropy source is reset to drop all existing
  time stamps and the startup testing is performed again.

#par(first-line-indent: 0pt)[The health tests are only applied when the
kernel operates in FIPS mode (booted with `fips=1`). The stuck test of section
@sec:90b-44 is applied in any case: stuck time stamps are never stored in the
event ring.]

=== SP800-90B Section 4.3 Requirement 8 <sec:90b-43-8>

There are no currently known suspected noise source failure modes.

=== SP800-90B Section 4.3 Requirement 9 <sec:90b-43-9>

N/A as the noise source is pure software. The software is expected to execute
on hardware operating in its defined nominal operating conditions.

=== SP800-90B Section 4.4 <sec:90b-44>

The health tests described in section @sec:health-tests are applicable to
cover the requirements of SP800-90B health tests. They are implemented in the
kernel module (esdm\_health.c) and parameterized with its oversampling rate
`ESDM_ES_OSR`.

The SP800-90B compliant health tests are implemented with the following
rationale:

/ RCT: The Repetition Count Test implemented by the kernel module compares
  two back-to-back time stamps to verify that they are not identical. In
  mathematical terms, the verification of back-to-back values being not
  identical is the calculation of the first discrete derivative of the time
  stamp to show that it is not zero. In addition, the kernel module enhances
  the RCT by calculating also the second and third discrete derivative of the
  time stamp. All derivatives must always be non-zero in order to pass the
  RCT. If one discrete derivative shows a zero, the time stamp is not stored
  and the RCT counter is increased; otherwise the counter is set to zero.
  Thus, the addition of the second and third derivative makes the RCT even
  more conservative. Hence, the first discrete derivative is considered to be
  identical to the “approved” RCT specified in SP800-90B section 4.4. In
  addition, linear and exponential patterns are identified with the second
  and third discrete derivative, respectively. As the additional pattern
  recognition do not invalidate the mandatory pattern recognition, this RCT
  approach therefore is considered to be an enhanced version of the
  “approved” RCT and thus meets the requirement (a) of SP800-90B section 4.5.

  The cutoff values are based on $alpha = 2^(-30)$ for an intermittent failure
  and $alpha = 2^(-60)$ for a permanent failure: 30 and 60 for one bit of
  entropy per time stamp, multiplied by the oversampling rate - 90 and 180
  for the default `ESDM_ES_OSR` of 3. A failure is raised when the counter
  exceeds the cutoff.

/ APT: The kernel module implements the Adaptive Proportion Test as defined
  in SP800-90B section 4.4.2. The APT is calculated using the four least
  significant bits of the time stamp. At the beginning of a window, a time
  stamp is set as a base. All subsequent time stamps of the window are
  compared to the base time stamp. If both values are identical, the APT
  counter is increased by one. The window size for the APT is 512 time
  stamps. The cutoff values depend on the oversampling rate: 325 and 355 for
  an oversampling rate of 1, 422 and 447 for 2, and 459 and 479 for the
  default of 3, for the intermittent and the permanent failure respectively
  (esdm\_health.h). The implementation therefore provides an “approved” APT.

== NIST Clarification Requests <sec:nist>

In addition to complying with the requirements of FIPS 140-2 and SP800-90B,
NIST requests the clarification of the following questions.

=== Sensitivity of Interrupt Timing Measurements <sec:nist-sensitivity>

The question that needs to be answered is whether the logic that measures the
interrupt timing is sensitive enough to pick up the variances of the interrupt
timing.

The sensitivity implies that timing variations are picked up and measured.
This is enforced by the stuck test enforced on each interrupt time stamp. That
stuck test requires that the first, second and third discrete derivative of
the time stamp must always be non-zero to accept that time stamp. Therefore,
the time stamp must vary for the received and processed interrupts which
implies that the health test ensures that the sensitivity of the time stamp
mechanism is sufficient.

=== Dependency Between Interrupt Timing Measurements <sec:nist-dependency>

Another question that is raised by NIST asks for a rationale why there are no
dependencies between individual Jitter measurements.

The interrupts are always created by either explicit or implicit human
actions. The ESDM measures the time stamp of the occurrence of these
interrupts. Thus, the ESDM measures the effects of operations triggered by
human interventions. With the presence of a high-resolution time stamp that
operates in the nanosecond range and the assumption that only one bit of
entropy is present in one nanosecond time stamp of one interrupt event, the
dependency discussion therefore focuses on the one (or maybe up to four) least
significant bit of the nanosecond time stamp. With such high-resolution time
stamps and considering that only the least significant bit(s) is/are relevant
for the ESDM, dependencies are considered to be not present for these bits.

== SP800-90B Compliant Configuration <sec:90b-config>

In order to use the interrupt entropy source SP800-90B compliant, the
following configurations and settings must be made.

The following compile-time settings must be observed:

- The kernel module must be compiled and loaded as documented in
  addon/linux\_esdm\_es/README.md, with the hook patches for the kernel
  version applied. Its Makefile must have the interrupt entropy source enabled
  (`BUILD_ES_IRQ=1`, the default) and `ESDM_ES_OSR` set to the oversampling
  rate resulting from the entropy assessment outlined in section
  @sec:90b-reuse. The kernel must be built with `CONFIG_CRYPTO_FIPS`, without
  which the module applies no oversampling of the conditioning.

- `es_irq` must be enabled in the ESDM to use the interrupt entropy source to
  which the entropy discussion of this chapter applies to.

- The configuration option `es_irq_entropy_rate` of the ESDM must be greater
  than zero; it can only lower the entropy rate of the kernel module. The
  scheduler-based entropy sources and the eBPF interrupt entropy source must
  not be credited with entropy at the same time - the ESDM build refuses a
  configuration crediting more than one of them.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The kernel must be booted with the kernel command line option of `fips=1` to
  enable the SP800-90B health tests and the oversampling.

#par(first-line-indent: 0pt)[To verify that the SP800-90B compliance is
achieved, the status of the interrupt entropy source - shown by `esdm-tool
--status`, the file /proc/sys/kernel/random/esdm\_type of `esdm-proc` or the
`esdm_rpcc_status` RPC API call - lists “SP800-90B” as its standards
compliance once the startup health tests completed; the kernel module reports
it (`esdm_irq_es_state_json`).]

To achieve a compliant configuration to SP800-90A and SP800-90B, the following
requirements must be met:

- All requirements for SP800-90B documented in section @sec:90b-config must be
  met.

- The DRNG of the ESDM must be an SP800-90A DRBG: the Hash DRBG of the builtin
  crypto backend (compile time option `drng_hash_drbg`, enabled by default)
  or an SP800-90A DRBG of another crypto backend (section @sec:backends).

#par(first-line-indent: 0pt)[Only data obtained from the potentially blocking
output interfaces of the ESDM are SP800-90B compliant (section
@sec:health-tests). If SP800-90C compliance is requested, these interfaces are
also providing SP800-90C compliant output.]

== Reuse of SP800-90B Analysis <sec:90b-reuse>

To reuse the SP800-90B analysis provided in this document the following steps
must be performed on the target platform:

+ Obtain raw noise data through the raw noise source interface
  `/sys/kernel/debug/esdm_es/esdm_raw_hires` on the intended target platform
  as explained in section @sec:90b-313:
  `esdm-getrawentropy --debugfs-file /sys/kernel/debug/esdm_es/esdm_raw_hires
  --samples 1000000`. The obtained raw noise data must be processed by
  `esdm-extractlsb` and the SP800-90B tool to obtain an entropy rate per time
  stamp which must be at least the rate credited by the kernel module,
  $1 \/ #raw("ESDM_ES_OSR")$ bit.

+ Obtain the restart noise data through the raw noise source interface on the
  intended target platform as explained in section @sec:90b-314. The obtained
  raw noise data must be processed by the SP800-90B tool to verify:

  + the sanity test to apply to the noise restart data must pass, and

  + the minimum of the row-wise and column-wise entropy rate must not be less
    than half of the entropy rate from measurement (1) and the entropy
    assessment of the noise source based on the restart data must be at least
    entropy rate per time stamp mentioned in (1).

#par(first-line-indent: 0pt)[If these steps are successfully mastered the user
would now satisfy all SP800-90B criteria and thus does not need to prepare his
own SP800-90B analysis since the document we discuss here covers all other
aspects of the SP800-90B analysis.]

The tool set provided as part of the ESDM code distribution provides the
measurements and validation tools (addon/test, built with the meson option
`validation-helpers`). For the eBPF-based entropy sources, the corresponding
procedure, including the restart test, is documented in
addon/es\_ebpf\_testing/README.md.
