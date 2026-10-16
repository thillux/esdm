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

The entropy sources of the auxiliary pool, the Jitter RNG and the CPU-based
entropy source are all not related to the interrupt entropy source. Thus, the
combination of all those entropy sources is subject to the SP800-90C
assessment provided in section @sec:sp80090c

== Noise Source Behavior <sec:noise-source>

The noise source component of an entropy source contains the
non-deterministic, entropy-producing activity. For the scheduler entropy
source this is the timing of the arrival of interrupts. The general behavior
of the noise source can be characterized by analyzing the time stamps of the
arrival time. Before performing this analysis, a recap of the noise source is
important:

- When a scheduling event occurs, the ESDM obtains a high-resolution time
  stamp. Technically it may be a cycle counter offered by the CPU that
  produces the time stamp which is unrelated to time, but provides a
  fast-moving counter.

- The time stamp is divided by the greatest common divisor (GCD) that is
  calculated during boot time by using the first 100 time stamps.

- After the division with the GCD, the 8 least-significant bits of the time
  stamp are used. The higher-order bits are discarded. These 8 bits are now
  subject to post-processing via the collection pool, the entropy pool and the
  DRNG.

#par(first-line-indent: 0pt)[Considering these static and never-changing
steps, the noise source rests on the gathering of the 8 bits from the last
step. An analysis of the noise source therefore focuses on these 8 bits. These
8 bits are subsequently referenced as “raw noise source data”.]

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

- Raw Entropy Tests: The tests obtain the raw unconditioned and unprocessed
  noise information and records it for analysis with the SP800-90B non-IID
  statistical test tool. The test tool includes the gathering of raw entropy
  for one execution run as well as for the restart tests required in SP800-90B
  section 3.1.4. The tool adjusts the data to be processed by the SP800-90B
  statistical test tool. The test tool provides the SP800-90B minimum entropy
  values.

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
ESDM. Instead of having these interrupts processed by the ESDM to add them to
the entropy pool, they are sent to a user space application for storing them
to disk.

The collection of the interrupt data for the raw entropy testing is invoked
from the same code path that would otherwise add it to the ESDM entropy pool.
Thus, the test collects the exact same data that would otherwise have been
used by the ESDM as noise data. Thus, the testing does not alter the ESDM
processing.

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

The ESDM uses the following conditioning components:

- For collecting of entropy data from the entropy source, an approved message
  digest operation is used.

- For reading the entropy pool and compressing the entropy data, the hash
  operation is used. The security strength of the ESDM is the minimum of the
  DRBG security strength and the security strength of the hash following
  @sp80090b section 3.1.5.1.1 table 1. All ciphers can be tested via ACVT.

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

The ESDM continuously gathers time stamps to be combined with a hash which is
entropy preserving. The hash operation function providing data to the DRNG
gathers only as much bits as time stamps were received. For example, if the
ESDM only received 16 time stamps, the ESDM will only deliver 2 bytes of data
to the DRNG. This effectively implies that the ESDM assumes that one bit of
entropy is received per time stamp.

As the ESDM maintains an entropy pool, its entropy content cannot be larger
than the pool itself. Thus, the entropy content in the pool after collecting
as many time stamps as the entropy pool's size in bits is the maximum amount
of entropy that can be held. Yet, as new time stamps are received, they are
mixed into the entropy pool. In case the entropy pool is considered to have
fully entropy, existing entropy is overwritten with new entropy.

This implies that the ESDM data generated from the entropy pool has (close
to) 1 bit of entropy per data bit.

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
believed to have more than one bit of entropy per time stamp to allow to
conclude that one output block of the ESDM has (close to) one bit of entropy
per data bit. Yet, this rate can be configured at compile time to be lower
than one bit of entropy per interrupt event.

The first test referenced in section @sec:ig718-testing performs the following
operations to provide the SP800-90B minimum entropy estimate:

+ Gathering of the raw entropy data of the time stamps.

+ Obtaining the four least significant bits of each time stamp and concatenate
  them to form a bit stream.

+ The bit stream is processed with the SP800-90B entropy testing tool to
  gather the minimum entropy.

#par(first-line-indent: 0pt)[For example, on an Intel Core i7 Skylake system
executing the ESDM in a KVM guest, the SP800-90B tool shows the following
minimum entropy values when multiplying the SP800-90B tool bit-wise minimum
entropy by four since four bits are processed: 3.452064.]

=== SP800-90B Section 3.1.4 <sec:90b-314>

For the restart tests, the raw entropy data is collected for the first 1,000
interrupt events received by the ESDM after a reboot of the operating system.
That means, for one collection of raw entropy the test system is rebooted.
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

The conditioning component applied to the interrupt entropy source are
performed at different stages as outlined in section @sec:components. Although
the hashing operation is used for different stages, the following discussion
is applicable to all use cases.

#paragraph[Truncation][The truncation operation ensures that the entropy in
that data is at maximum the truncated hash.]

The truncation of operation (1) listed in section @sec:data-processing is not
affected by the capping of the entropy, because the quantitative measurement
of the existing entropy using the SP800-90B tool set is performed using that
truncated input data. The ESDM implies an entropy of 1 bit per truncated time
stamp and zero bits of entropy per arbitrary 32-bit word size which means that
the entropy present in the data is always smaller as the data size.

The truncation operation of step (6) listed in section @sec:data-processing
verifies that the truncated data contains at most the amount of entropy as
the generated data size. The remaining part of the truncated data is not
exported to any external entity but remains in the per-CPU entropy pools -
when new random data is generated involving the entropy pools, the current
entropy pool states are always hashed. This is a deviation from SP800-90B
section 3.1.5.1.2 which requires a relative reduction of entropy. This
statement is considered inconsistent with the statement implied in table 1
@sp80090b and therefore wrong depicted with the following analogy: Assume to
have a buffer of 512 bits of data having 256 bits of entropy. When hashing it
with SHA-512, the resulting message digest of 512 bits has 256 bits of
entropy. When truncating the digest to 256 bits, SP800-90B states the entropy
is 128 bits. However, SP800-90B section 3.1.5.1.1 table 1 states that full
entropy is given to approved hash functions. Assume to use a SHA-512/256 which
has a digest size of 256 bits and thus could transport 256 bits of entropy
following table 1. This SHA-512/256 hash operation calculates a SHA-512 hash
truncated to 256 bits. Albeit the cryptographic operation of SHA-512/256 is
identical to the ESDM-applied truncation#footnote[Depending on the runtime
configuration the ESDM uses a hash of SHA-512 and fills a buffer of the DRNG
security strength size, i.e. 256 bits.], SP800-90B table 1 awards 256 bits of
entropy to SHA-512/256 but at the same time SP800-90B would apply only 128
bits to the ESDM-applied truncation. Due to this inconsistency, the ESDM
applies the entropy behavior implicitly specified in table 1, i.e. the entropy
is the minimum of the available entropy and the message digest size.
Furthermore, applying the Output\_Entropy formula for a vetted conditioning
component of a truncated hash, the following calculation applies. This
calculation shows the entropy rate of a SHA-512 hash processing a buffer with
1024 bits that contains, say, 384 bits of entropy and truncating it to 256
bits. This means, the formula for
$h_("out"_("SHA-512 trunc")) = OE_("SHA-512 trunc")(1024, 256, 512, 384)$
following @sp80090b section 3.1.5.1.2 is calculated:

#display($P_"high" = 2^(-384)$)
#display($P_"low" = (1 - 2^(-384)) / (2^1024 - 1) approx 2^(-1024)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(1024-256) dot 2^(-1024) + 2^(-384) = 2^(-256) + 2^(-384)
  approx 2^(-256) \
  U = 2^(1024-256) + sqrt(2 dot 256 dot (2^(1024-256)) dot ln(2))
  = 2^768 + sqrt(2^777 dot ln(2)) approx 2^768 \
  omega = 2^768 times 2^(-1024) = 2^(-256) \
  underline(OE_("SHA-512 trunc")(1024, 256, 512, 384)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

Even after calculating other entropy rates using the same formula, the
following conclusion for the truncation can be applied:

#display($underline(OE_"trunc" (n_"in", n_"out", n w, h_"in")
  = min(n_"in", n_"out", n w, h_"in"))$)

This function is applied by the ESDM for hash truncation.

#paragraph[Concatenation][When applying a concatenation operation, the ESDM
simply adds the entropy delivered with each data entry part.]

#paragraph[Hash][The input of the hash $n_"in"$ is fixed as it processes the
existing per-CPU entropy pool(s), auxiliary pool and the per-CPU collection
pools.]

The output of the hash $n_"out"$ is usually fixed to the message digest size.
The on exception is the output of the hash $n_"out"$ to provide the seed to
the DRNG: it is the minimum of either the digest size of the used hash or the
amount of entropy available in the processed entropy pools based on the number
of “unprocessed” time stamps held in the per-CPU entropy pools.

The following hashes are used for the hash function depending on the loaded
DRNG:

- ChaCha20: SHA-256 in normal case, SHA-1 if kernel is not compiled with
  CONFIG\_CRYPTO

- SP800-90A Hash DRBG: SHA-512

- SP800-90A HMAC DRBG: SHA-512

- SP800-90A CTR DRBG: SHA-512

#par(first-line-indent: 0pt)[In the following, the different hash operations
specified in section @sec:data-processing are applied as follows:]

- Compression of entropy delivered from the interrupt entropy source when
  adding the entropy into the per-CPU entropy pools.

- Compression of entropy delivered from one or more ESDM-external entropy
  sources when adding the entropy into the auxiliary pool.

- Compression of entropy delivered by the different per-CPU entropy pools when
  “reading” the entropy pools.

#par(first-line-indent: 0pt)[The requirement of @sp80090b section 3.1.6
states that when combining two or more noise sources using a vetted
conditioning component, only one noise source is to be credited with entropy.
This requirement is met as follows: according to @sp80090b section 2.2 a noise
source is the phenomenon delivering entropy. The noise source data is
post-processed with conditioning components and health tests to form an
entropy source. Based on this statement, the collection of the per-CPU entropy
pools together form one entropy source that is compliant to SP800-90B.]

Note, the reason for hashing the per-CPU entropy pools together with the
auxiliary pool is to ensure backward secrecy when calculating the next round
of random numbers used to fill the seed buffer used to seed the DRBG from the
entropy sources sources.

#paragraph[Approach for Calculating Entropy][Although the aforementioned
sections explain that the input and output sizes may not be fixed, in regular
operation they are quasi-fixed. In order to reseed a DRNG, 256 bits of entropy
are to be generated from the noise source. Although the per-CPU collection
pools receive interrupt time stamps continuously, only the entropy from 256
time stamps are required as illustrated below. Only when all per-CPU entropy
pools have received too little interrupt time stamps to satisfy the 256 bit
entropy request, less output data is generated. This commonly happens during
boot or at runtime when too much entropy is requested. Though, during boot
time, the DRNG will receive a (re)seed with 256 bits of entropy before the
ESDM is considered fully operational. Therefore, the prior boot-time (re)seed
events with less entropy may even be disregarded for the entropy assessment.]

With the given combination of the hash as outlined above, the following
approach for the entropy calculation is taken for each of the data processing
steps outlined in section @sec:data-processing:

- Function @eq:ep-cpu:

  - $n_("in"_("per-CPU pool"))$ equals to 8,192 bits as the per-CPU entropy
    pool obtains its input data from the collection pool that has a size of
    8,192 bits (1,024 \* 8 bits)#footnote[Section ?? outlines that the ESDM
    collection size can be modified at compile time where the default is
    1,024. When a different collection size is chosen, the value needs to be
    adjusted accordingly. Yet, such modified value has no impact to the
    entropy analysis.] .

  - $n_("out"_("per-CPU pool"))$ is the message digest size in bits.

  - $n w_("per-CPU pool")$ is the message digest size in bits.

- Function @eq:ap:

  - $n_("in"_("aux pool"))$ equals to 512 bits as the auxiliary pool pool size
    is 512 bits in size plus the provided input data.

  - $n_("out"_("aux pool"))$ is the message digest size in bits.

  - $n w_("aux pool")$ is the message digest size in bits.

- Function @eq:ep-all:

  - $n_("in"_("hash pools"))$ equals to
    $sum_(a=0)^("max CPU") n_("out"_("per-CPU pool"_a))
    + n_("out"_("hash aux"))$

  - $n_("out"_("hash pools"))$ is the message digest size in bits.

  - $n w_("hash pools")$ is the message digest size in bits.

=== SP800-90B Section 3.1.5.1 <sec:90b-3151>

The hash operation is either SHA-512, SHA-256, or SHA-1 as outlined above is
considered to be a vetted conditioning component. Thus the entropy rate of the
hash output is calculated as follows using the aforementioned variables for
the hash function. In addition, the following consideration applies:

- The entropy content of the input $h_("in"_("per-CPU pool"))$: The input
  entropy of the hash used to process the per-CPU entropy pool is equal to the
  entropy provided by the per-CPU collection pool and the entropy already
  present in the per-CPU entropy pool considering that both data components
  are hashed at the same time to form a new per-CPU entropy pool state. Of
  course, the entropy held in the per-CPU entropy pool will never be larger
  than the digest size of the used hash which is compliant to @sp80090b
  section 3.1.5.1.1 table 1.

- The entropy content of the input $h_("in"_("aux pool"))$: The input entropy
  of the hash used to process the auxiliary pool is equal to the entropy
  provided by the noise source and the already collected entropy in the
  auxiliary pool considering that both data components are hashed at the same
  time to form a new auxiliary pool state. Of course, the entropy held in the
  auxiliary pool will never be larger than the digest size of the used hash
  which is compliant to @sp80090b section 3.1.5.1.1 table 1.

- The entropy content of the input $h_("in"_("hash pools"))$: The input
  entropy of the hash used to process the entire entropy pool is equal to the
  entropy found in all per-CPU entropy pools managed by the hash operation and
  the auxiliary pool. Again, the entropy generated by the hash will never be
  larger than the digest size of the used hash which is compliant to
  @sp80090b section 3.1.5.1.1 table 1.

#paragraph[Function @eq:ep-cpu Output\_Entropy][To perform a calculation of
the Output\_Entropy of a conditioning component, the input entropy must be
considered. The heuristic input entropy awarded for one time stamp processed
by the ESDM is given in equation @eq:h-t. Due to the concatenation operation
of time stamps, the entropy of multiple time stamps can be added.]

For the function @eq:ep-cpu, the entropy when 1,024 time stamps are received
is $h_("out"_("SHA-512")) = OE_("SHA-512")(8192, 512, 512, 1024)$ following
@sp80090b section 3.1.5.1.2. Therefore, the following calculation is
applicable:

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

As a complement, the same calculation is provided when only one time stamp is
received for the formula
$h_("out"_("SHA-512")) = OE_("SHA-512")(8, 512, 512, 1)$

#display($P_"high" = 2^(-1)$)
#display($P_"low" = (1 - 2^(-1)) / (2^8 - 1) approx 2^(-9)$)
#display($n = min(512, 512) = 512$)
#display($psi = 2^(8-512) dot 2^(-9) + 2^(-1) = 2^(-513) + 2^(-1)
  approx 2^(-1) \
  U = 2^(8-512) + sqrt(2 dot 512 dot (2^(8-512)) dot ln(2))
  = 2^(-504) + sqrt(2^(-494) dot ln(2)) approx 2^(-247) dot sqrt(ln(2))
  approx 2^(-248) \
  omega = 2^(-248) times 2^(-9) = 2^(-257) \
  underline(OE_("SHA-512")(8, 512, 512, 1)
  = -log_2(max(2^(-257), 2^(-1))) = 1)$)

The calculation can be generalized with the following formula:

#display($h_("out"_("SHA-512")) = OE_("SHA-512")
  = min(h_"in", n_("out"_("SHA-512")))$)

When using SHA-256, the same type of calculation can be provided. The first
set of formulas show the case when 1,024 time stamps are received and thus for
$h_("out"_("SHA-256")) = OE_("SHA-256")(8192, 256, 256, 1024)$:

#display($P_"high" = 2^(-1024)$)
#display($P_"low" = (1 - 2^(-1024)) / (2^8192 - 1) approx 2^(-8192)$)
#display($n = min(256, 256) = 256$)
#display($psi = 2^(8192-256) dot 2^(-8192) + 2^(-1024) = 2^(-256) + 2^(-1024)
  approx 2^(-256) \
  U = 2^(8192-256) + sqrt(2 dot 256 dot (2^(8192-256)) dot ln(2))
  = 2^7936 + sqrt(2^7945 dot ln(2)) approx 2^7936 \
  omega = 2^7936 times 2^(-8192) = 2^(-256) \
  underline(OE_("SHA-256")(8192, 256, 256, 1024)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

As a complement, the same calculation is provided when only one time stamp is
received for the formula
$h_("out"_("SHA-512")) = OE_("SHA-256")(8, 256, 256, 1)$

#display($P_"high" = 2^(-1)$)
#display($P_"low" = (1 - 2^(-1)) / (2^8 - 1) approx 2^(-9)$)
#display($n = min(256, 256) = 256$)
#display($psi = 2^(8-256) dot 2^(-9) + 2^(-1) = 2^(-257) + 2^(-1)
  approx 2^(-1) \
  U = 2^(8-256) + sqrt(2 dot 256 dot (2^(8-256)) dot ln(2))
  = 2^(-248) + sqrt(2^(-239) dot ln(2)) approx 2^(-120) dot sqrt(ln(2))
  approx 2^(-121) \
  omega = 2^(-121) times 2^(-9) = 2^(-130) \
  underline(OE_("SHA-256")(8, 256, 256, 1)
  = -log_2(max(2^(-130), 2^(-1))) = 1)$)

Again, the calculation can be generalized with the following formula:

#display($h_("out"_("SHA-256")) = OE_("SHA-256")
  = min(h_"in", n_("out"_("SHA-256")))$)

Comparing the conclusions for SHA-512 and SHA-256, both allow to draw the
general conclusion that underlies the entire entropy assessment and therefore
data entropy management applied by the ESDM for all vetted conditioning
operations:

$ h_("out"_"vetted") = OE_"vetted" = min(h_"in", n_("out"_"vetted")) $
<eq:vetted>

#paragraph[Function @eq:ap][The function @eq:ap uses the same hash operation
as the discussed in the preceding section. Thus, the conclusion drawn with
equation @eq:vetted applies here as well.]

#paragraph[Function @eq:ep-all][The function @eq:ep-all uses the same hash
operation as the discussed in the preceding section. Thus, the conclusion
drawn with equation @eq:vetted applies here as well.]

#paragraph[Conclusions for Output\_Entropy][As stated in @sp80090b section
3.1.5.1.2, vetted conditioning components are allowed to claim full entropy.
In case of full entropy, the following is applied which matches exactly
analysis and conclusion of equation @eq:vetted:]

- $h_("out"_("SHA-512")) = min(h_"in", n_("out"_("SHA-512")))$,

- $h_("out"_("SHA-256")) = min(h_"in", n_("out"_("SHA-256")))$, or

- $h_("out"_("SHA-1")) = min(h_"in", n_("out"_("SHA-160")))$.

#par(first-line-indent: 0pt)[Based on that conclusion, the entropy rate for
each processing step given in section @sec:data-processing can be illustrated
in the following. This entropy assessment uses $n_"out"$ which depends on the
chosen hash operation with the respective value listed above for the chosen
hash.]

#paragraph[Heuristic Entropy Assessment][The heuristic entropy value for the
individual time stamps is defined with the following equation applicable when
a high-resolution timer is present – the absence of a high-resolution timer
automatically implies the ESDM is treated as non-compliant to SP800-90B:]

$ h_(t_8) = h_(t_32) = 1 $ <eq:h-t>

Note, in order to assess whether the ESDM heuristic entropy value is
appropriate, it must be compared with the entropy analysis result received
from practical measurements such as outlined in sections @sec:90b-313 and
@sec:90b-314. This comparison must show that the heuristic entropy value is
always lower and thus more conservative than what the measurements show on
target devices.

The entropy present in the arbitrary 32 bit word that may be added to the
per-CPU collection pool is defined with:

$ h_(a_32) = 0 $ <eq:h-a>

The entropy in the concatenated time stamps found in the interrupt as well as
scheduler per-CPU collection pool is calculated as the sum of all time stamps
(truncated or not) present in the interrupt as well as scheduler per-CPU
collection pool of 1,024 bytes per default – if a different collection pool
size is used, the right-hand value of the following equation must be adjusted
accordingly:

$ h_("per-CPU CP") = min(sum_(n=0)^("number time stamps")
  (h_(t_({8,32})))_n, 1024) $ <eq:h-cp>

For the maintenance of the interrupt per-CPU entropy pool as specified by
equation @eq:ep-cpu, the following entropy rate applies when continuous
compression support is enabled. This formula implies that each output of the
interrupt per-CPU entropy pool holds the sum of the entropy of the received
per-CPU collection pool since last generation of the per-CPU output data and
the entropy remained in the per-CPU entropy pool capped by the message digest
size. This operation implies that the used hash compresses of the entropy
available in the different input data.

$ h_("per-CPU pool"_n) = min(sum_(m=0)^(m=n-1) h_("per-CPU CP"_m)
  + h_("per-CPU pool"_(n-1)), n_"out") $ <eq:h-pool-cc>

When continuous compression support is disabled as well as for the
scheduler-based entropy source, the per-CPU entropy pool maintenance
specified by equation @eq:ep-cpu shows the following entropy rate. The
formula implies that the maximum amount of entropy that can be held depends
on the size of the collection pool depicted with equation @eq:cp since
additional entropy received by the collection pool overwrites old entropy
data. The collection pool can hold the maximum amount of entropy event data as
defined with its size. After converting the number of received entropy event
data into an entropy statement using equation @eq:h-t, the maximum amount of
entropy held in the collection pool is available.

$ h_("per-CPU pool"_n) = min(h_("per-CPU CP"_n) + h_("per-CPU pool"_(n-1)),
  n_"out") $ <eq:h-pool>

Similarly, the following equation applies to the entropy of the auxiliary pool
maintenance as specified by equation @eq:ap. Note, although this entropy
source is not considered to be modeled in this chapter, the formula is still
provided illustrating the use of a vetted conditioning component. This
formula implies that auxiliary pool holds the sum of the entropy of the
received data capped by the message digest size. Again, this operation implies
that the used hash compresses the entropy available in the different input
data.

$ h_("aux pool") = min(h_("in"_("aux pool")) + h_("aux pool"), n_"out") $
<eq:h-aux>

The following equation applies when calculating the interrupt and
scheduler-based entropy source output buffer before its truncation as
specified by equation @eq:ep-all. The formula implies that the interrupt
entropy source buffer before truncation holds the sum of the entropy of all
per-CPU entropy pools plus the auxiliary pool capped by the message digest
size. Again, this operation implies that the used hash compresses the entropy
available in the different input data.

$ h_("hash pools") = min(sum_(c=0)^("max CPU") h_("per-CPU pool"_c),
  n_"out") $ <eq:h-hash-pools>

The entropy present in the truncated interrupt and scheduler-based entropy
source buffer is the minimum of the entropy found in the pools and the
requested amount of bits which is equal to the security strength of the DRBG:

$ "requested size"_s = "security strength" = 256 $ <eq:requested>

$ h_s = min(h_("hash pools"), "requested size"_s) $ <eq:h-s>

The entropy of the temporary seed buffer following equation @eq:vetted is
simply an addition of the entropy values credited for each of the entropy
source with $h_A$ denominating the auxiliary entropy entropy rate, $h_E$
references the IRQ ES entropy rate, , $h_S$ references the scheduler ES
entropy rate, , $h_J$ covers the Jitter RNG ES entropy rate, $h_C$ references
the CPU ES entropy rate, $h_K$ references the kernel ES entropy rate, and
$h_H$ denominates the HWRAND entropy source:

$ h_T = h_A + h_E + h_S + h_J + h_C + h_K + h_H $ <eq:h-t-buffer>

The result of the formulas show that the entropy is simply a sum of the
entropy of all input events capped to the message digest size of the used hash
operation.

When generating the random numbers filling the interrupt entropy source
buffer, the entropy is debited in the following steps. First the entropy
estimator of the auxiliary pool is reduced as much as possible: either by
$h_s$ or at most to zero. If not all entropy of $h_s$ could have been debited
from the auxiliary pool entropy estimator, then the yet not debited part of
$h_s$ is debited from the per-CPU entropy pool entropy estimators.

For example, assume that after the generation of random numbers and filling
the slow noise source buffer its entropy is $h_s = 256$. Assume further, the
per-CPU entropy pools of the assumed 2 CPUs contain
$h_("per-CPU pool"_("CPU0")) = 185$ and $h_("per-CPU pool"_("CPU1")) = 123$.
The debit operation performs:

+ $h_("per-CPU pool"_("CPU0")) = 185 - 185 = 0$ leaving
  $h_(s_"not debited") = 256 - 185 = 71$

+ $h_("per-CPU pool"_("CPU1")) = 123 - 71 = 52$

=== SP800-90B Section 3.1.6 <sec:90b-316>

The ESDM uses the following noise sources for the interrupt entropy source:

- The noise source of the timing of the occurrence of interrupts. The entire
  SP800-90B analysis covers this one noise source. Thus, the requirements in
  this section for the interrupt noise source are trivially met.

- Auxiliary data delivered as part of interrupts: HID event data. This data is
  concatenated with the interrupt time stamps into the collection pool. Yet it
  is always credited with zero bits of entropy.

#par(first-line-indent: 0pt)[All data is processed by the vetted conditioning
component of the hash before it is injected as seed data into the DRNG. Thus,
this operation complies with the last paragraph of section 3.1.6.]

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
of the software delivery. This source code contains API calls which are to be
used by entities using the ESDM.

=== SP800-90B Section 3.2.1 Requirement 5 <sec:90b-321-5>

The per-CPU entropy pools as processed by the hash is the output of the
interrupt noise source. I.e. the entropy pools maintained by the hashing
operation holds the data that is given to the DRNG when requesting seeding.

The noise source output without the hashing operation is accessed with
specific tools which add interfaces that are not present and thus not usable
when employing the ESDM in production mode. These additional interfaces are
used for gathering the data used for the analysis documented in section
@sec:90b-313. These interfaces perform the following operation:

+ Switch the ESDM into raw entropy generation mode. This implies that each raw
  entropy event is fed to the raw entropy collection interface and not
  processed by the per-CPU collection pool or otherwise used.

+ When an interrupt event is received, forward the time stamp holding the
  entropy to a ring buffer. This operation is performed repeatedly until the
  ring buffer is full or the user space application read that ring buffer.

+ When an application requests the reading of the ring buffer, the data is
  extracted from the kernel and the ring buffer is cleared.

#par(first-line-indent: 0pt)[With this approach, the actual interrupt events
which would be processed by the ESDM are obtained.]

The kernel interface is only present if the kernel is compiled with the
option CONFIG\_ESDM\_RAW\_HIRES\_ENTROPY. This option should not be set in
production kernels.

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

The noise source generates the data via the hash generation function as
outlined in section @sec:90b-315.

Although the hash commonly generates a fixed-length string, this string length
may be reduced by the amount of available entropy as outlined in section
@sec:90b-3151.

=== SP800-90B Section 3.2.2 Requirement 7 <sec:90b-322-7>

N/A as no additional noise source is implemented with the interrupt entropy
source.

Though, the ESDM employs complete self-contained other entropy sources which
may be compliant to SP800-90B by itself. To seed the DRNG maintained by the
ESDM, the output of all entropy sources are concatenated compliant to
SP800-90C as outlined in section @sec:sp80090c.

=== SP800-90B Section 3.2.3 Requirement 1 <sec:90b-323-1>

The conditioning component is the hash operation. See section @sec:90b-315
for a discussion of the input and output sizes.

=== SP800-90B Section 3.2.3 Requirement 2 <sec:90b-323-2>

The used hash implementations for the conditioning components functions are
all ACVP-testable. The ESDM offers an ACVP interface to ensure also the
built-in SHA-256 and SHA-1 implementations are testable.

=== SP800-90B Section 3.2.3 Requirement 3 <sec:90b-323-3>

For the defined hashes, no key is required.

=== SP800-90B Section 3.2.3 Requirement 4 <sec:90b-323-4>

For the defined hashes, no key is required.

=== SP800-90B Section 3.2.3 Requirement 5 <sec:90b-323-5>

The conditioning component is the hash operation. See section @sec:90b-3151
for a discussion of the narrowest internal width and the output block size.

=== SP800-90B Section 3.2.4 Requirement 1 <sec:90b-324-1>

Test tools for measuring raw entropy are provided at the
#link("https://www.chronox.de/esdm")[ESDM web page.] These tools can be used
by everybody without further knowledge of the ESDM.

=== SP800-90B Section 3.2.4 Requirement 2 <sec:90b-324-2>

The operation of the test tools for gathering raw data are discussed in
section @sec:90b-313. This explanation shows that the raw unconditioned data
is obtained.

=== SP800-90B Section 3.2.4 Requirement 3 <sec:90b-324-3>

The provided tools for gathering raw entropy contains exact steps how to
perform the tests. These steps do not require any knowledge of the noise
source.

=== SP800-90B Section 3.2.4 Requirement 4 <sec:90b-324-4>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated under normal operating conditions.

=== SP800-90B Section 3.2.4 Requirement 5 <sec:90b-324-5>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated on the same hardware and operating system
that executes the ESDM.

=== SP800-90B Section 3.2.4 Requirement 6 <sec:90b-324-6>

The test tools are publicly available at
#link("https://www.chronox.de/lrng")[LRNG web page] allowing the replication
of any raw entropy measurements.

=== SP800-90B Section 3.2.4 Requirement 7 <sec:90b-324-7>

Please see section @sec:ig718-c1 for details how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP800-90B Section 4.3 Requirement 1 <sec:90b-43-1>

The implemented health tests comply with SP800-90B sections 4.4 as described
in section @sec:90b-44.

=== SP800-90B Section 4.3 Requirement 2 <sec:90b-43-2>

When either health test fails, the kernel:

- Emits a failure log,

- Resets the noise source, and

- Restarts the SP800-90B startup health tests.

#par(first-line-indent: 0pt)[This implies that no data is produced by the
ESDM (including its DRNG) when using the SP800-90B compliant external
interfaces.]

Both health test failures are considered permanent failures and thus trigger
a full reset.

=== SP800-90B Section 4.3 Requirement 3 <sec:90b-43-3>

The following false positive probability rates are applied:

- RCT: The false positive rate is $alpha = 2^(-30)$ and therefore complies
  with the recommended false positive probability.

- APT: The cut-off value is set to 325 compliant to SP800-90B section 4.4.2
  for non-binary data at a significance level of $alpha = 2^(-30)$ with time
  stamp is assumed to at least provide one bit of entropy, i.e.
  H = 1#footnote[Note, the referenced Excel function seems to be imprecise
  when calculating the value. The data has been obtained using R-Project with
  the formula of $1 + "qbinom"(1 - 2^(-30), 512, 2^(-1))$.].

=== SP800-90B Section 4.3 Requirement 4 <sec:90b-43-4>

The ESDM applies a startup health test of 1,024 noise source samples.
Additional tests are applied. The collected noise source samples are re-used
for the generation of random numbers if the startup test was successful.

=== SP800-90B Section 4.3 Requirement 5 <sec:90b-43-5>

The noise source supports on-demand testing in the sense that the caller may
restart the kernel.

=== SP800-90B Section 4.3 Requirement 6 <sec:90b-43-6>

The health tests are applied to the raw, unconditioned time stamp data
directly obtained from the noise source before they are injected into the
per-CPU collection pool and further processed with the hash conditioning
component.

=== SP800-90B Section 4.3 Requirement 7 <sec:90b-43-7>

The health tests are documented with section @sec:health-tests.

The tests are executed as follows:

- During startup, the RCT and the APT are applied to 1,024 samples. The
  startup test can be triggered again when the caller reboots the kernel.

- At runtime, the RCT is applied to each received time stamp. The APT collects
  512 time stamps. The APT is calculated over all 512 time stamps. If the test
  fails, the entire ESDM is reset to drop all existing entropy and the startup
  testing is performed again.

=== SP800-90B Section 4.3 Requirement 8 <sec:90b-43-8>

There are no currently known suspected noise source failure modes.

=== SP800-90B Section 4.3 Requirement 9 <sec:90b-43-9>

N/A as the noise source is pure software. The software is expected to execute
on hardware operating in its defined nominal operating conditions.

=== SP800-90B Section 4.4 <sec:90b-44>

The health tests described in section @sec:health-tests are applicable to
cover the requirements of SP800-90B health tests.

The SP800-90B compliant health tests are implemented with the following
rationale:

/ RCT: The Repetition Count Test implemented by the ESDM compares two
  back-to-back time stamps to verify that they are not identical. If the
  number of identical back-to-back time stamps reaches the cut-off value of
  30, the RCT test raises a failure that is reported and causes a reset the
  ESDM. The RCT uses the a cut-off value that is based on the following:
  $alpha = 2^(-30)$ compliant to FIPS 140-2 IG 9.8 and compliant to SP800-90B
  which mandates this value to be in the range
  $2^(-20) <= alpha <= 2^(-40)$. In addition, one time stamp is assumed to at
  least provide one bit of entropy, i.e. $H = 1$. When applying these values
  to the formula given in SP800-90B section 4.4.1, the cut-off value of 31 is
  calculated.

  When the RCT passes, the counter is set to zero for the next time delta to
  arrive. In mathematical terms, the verification of back-to-back values being
  not identical is the calculation of the first discrete derivative of the
  time stamp to show that it is not zero. In addition, the ESDM enhances the
  RCT by calculating also the second and third discrete derivative of the time
  stamp to be concatenated with the per-CPU collection pool. With that, up to
  8 consecutive time stamp values are assessed. All derivatives must always be
  non-zero in order to pass the RCT. If one discrete derivative shows a zero,
  the RCT counter is increased. Thus, the addition of the second and third
  derivative makes the RCT even more conservative. Hence, the first discrete
  derivative is considered to be identical to the “approved” RCT specified in
  SP800-90B section 4.4. In addition, linear and exponential patterns are
  identified with the second and third discrete derivative, respectively. As
  the additional pattern recognition do not invalidate the mandatory pattern
  recognition, this RCT approach therefore is considered to be an enhanced
  version of the “approved” RCT and thus meets the requirement (a) of
  SP800-90B section 4.5.

/ APT: The ESDM implements the Adaptive Proportion Test as defined in
  SP800-90B section 4.4.2. As explained in other parts of the document, one
  time stamp value is assumed to have (at least) one bit of entropy. Thus, the
  cut-off value for the APT is 325 compliant to SP800-90B section 4.4.2 for
  non-binary data with a significance level of $alpha = 2^(-30)$. The APT is
  calculated using the four least significant bits of the time stamp. During
  initialization of the APT, a time stamp is set as a base. All subsequent
  time stamps are compared to the base time stamp. If both values are
  identical, the APT counter is increased by one. The window size for the APT
  is 512 time stamps. The implementation therefore provides an “approved”
  APT.

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
implies that the ESDM health test ensures that the sensitivity of the time
stamp mechanism is sufficient.

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

In order to use the ESDM SP800-90B compliant, the following configurations
and settings must be made. These settings are cover requirements for the
compile-time options found in the ESDM meson configuration framework.

The following compile-time settings must be observed:

- `fips140` must be enabled.

- `es_irq` must be enabled to enable the interrupt entropy source to which the
  entropy discussion of this chapter applies to.

- Set the configuration option of `es_irq_entropy_rate` to the rate resulting
  from the entropy assessment outlined in section @sec:90b-reuse.

- The ESDM Linux kernel module must be enabled and compiled as documented in
  addon/linux\_esdm\_es/README.md. The Makefile in this directory must have
  the interrupt entropy source enabled.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The kernel must be booted with the kernel command line option of `fips=1` to
  enable the SP800-90B health test.

#par(first-line-indent: 0pt)[To verify that the SP800-90B compliance is
achieved, the file /proc/sys/kernel/random/esdm\_type or the
`esdm_rpcc_status` RPC API call provides an appropriate status indicator.]

To achieve a compliant configuration to SP800-90A and SP800-90B, the following
requirements must be met:

- All requirements for SP800-90B documented in section @sec:90b-config must be
  met.

- The ESDM compile time option `drng_hash_drbg` must be enabled which provides
  the SP800-90A DRBG.

#par(first-line-indent: 0pt)[Only data obtained from the potentially blocking
output interfaces of the ESDM are SP800-90B compliant. If SP800-90C compliance
is requested, these interfaces are also providing SP800-90C compliant output.
Finally, the following interfaces are DRG.3 compliant:]

- /dev/random,

- `getrandom` system call invoked with a zero flag value,

- invoking the in-kernel `esdm_get_random_bytes_full` API,

- invoking the in-kernel `esdm_get_random_bytes_pr` API that provides access
  to the DRBG operated with prediction resistance.

#par(first-line-indent: 0pt)[Any other interface is not considered to provide
SP880-90B compliant data.]

== Reuse of SP800-90B Analysis <sec:90b-reuse>

To reuse the SP800-90B analysis provided in this document the following steps
must be performed on the target platform:

+ Obtain raw noise data through the raw noise source interface on the intended
  target platform as explained in section @sec:90b-313. The obtained raw noise
  data must be processed by the SP800-90B tool to obtain an entropy rate which
  must be above the entropy rate per time delta that is configured with
  `es_irq_entropy_rate`: the entropy rate must be above
  $256 \/ #raw("es_irq_entropy_rate")$.

+ Obtain the restart noise data through the raw noise source interface on the
  intended target platform as explained in section @sec:90b-313. The obtained
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

The tool set provided as part of ESDM library code distribution provides the
measurements and validation tools.
