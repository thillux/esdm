#import "../template.typ": *

= Thanks <sec:thanks>

Special thanks for input and mathematical support go to:

- DJ Johnston

- Yi Mao

- Sandy Harris

- Dr. Matthias Peter

- Quentin Gouchet

= Source Code Availability <sec:source-code>

The source code, this document and the test code for all tests described
here are available at
#link("https://www.chronox.de/esdm")[`https://www.chronox.de/esdm`] and
#link("https://github.com/smuellerDD/esdm")[
`https://github.com/smuellerDD/esdm`.]

= SP 800-90B Entropy Measurements <sec:measurements>

The following table lists the #ac("SP") 800-90B entropy measurements. They show
whether the measured entropy is high enough to support the entropy analysis
of section @sec:90b-315. The entropy values are in bits and apply to one
timestamp generated for an interrupt event. The testing in this section
provides the quantitative foundation of the entropy analysis compliant with
section @sec:90b-3151 and of all other assessments that #ac("SP") 800-90B
requires.

The testing collected raw, unconditioned timestamps from the file
`/sys/kernel/debug/esdm_testing/esdm_raw_hires` of the kernel module version
used for the measurements. The current kernel module provides the
differences of successive timestamps in the file
`/sys/kernel/debug/esdm_es/esdm_raw_hires`, as section @sec:igdj-testing
outlines; section @sec:90b-313 lists its measurements of both entropy
sources. The entropy calculation uses 1,000,000 raw timestamps collected
by the #ac("ESDM"). To speed up the raw timestamp collection and to obtain a
worst-case assessment, either a ping flood or a `find /` in an #ac("SSH")
session generated a large number of interrupts on every test system in a short
time. The ping flood generator was close to the test system in the network (e.g.
the #ac("KVM") host, or a system at most one switch away from the test system).

The entropy results in the table below are generated as follows. The
timestamps the #ac("ESDM") generates for the interrupt events are extracted and
concatenated into a bit stream. The
#link("https://github.com/usnistgov/SP800-90B_EntropyAssessment/")[#ac("NIST", cap: true)
#ac("SP") 800-90B entropy analysis tool] processes this bit stream and yields
the entropy rate listed below. The #ac("ESDM") used the 8 #ac("LSB")
of the timestamp and ignored the other bits, so the entropy rate applies to
those 8 data bits. As discussed in section @sec:90b-3151, the #ac("ESDM")
assumes that each timestamp provides at least 1/`ESDM_ES_OSR` bit of
entropy, a third of a bit with the default oversampling rate. All values in
the table below show significantly more entropy, even in the worst-case
measurement of 8 #ac("LSB"). On each of these systems the credited
entropy thus lies below the measured estimate; section
@sec:measurement-limits states the limits of these measurements.
The test complies with #ac("SP") 800-90B as outlined in section @sec:90b-313.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(center + top)
    show table.cell.where(x: 0): set align(left + top)
    table(
      columns: (2.7fr, 1.4fr, 0.8fr),
      table.header(
        [Test System], [Entropy of \ 1,000,000 Traces],
        [Sufficient \ Entropy],
        table.hline(stroke: 0.8pt),
      ),
      [AMD Ryzen 5950X – 64-bit #ac("KVM") environment], [4.531023], [Y],
      [AMD EPYC Milan 7713 2 sockets 128 cores 8-way #ac("NUMA")], [7.007947],
      [Y], [ARMv7 rev 5], [1.9344], [Y],
      [ARMv7 rev 5 \ (Freescale i.MX53)#footnote[USBArmory MK I]],
        [7.07088], [Y],
      [ARMv7 rev 5 \ (Freescale i.MX6 Ultralite)#footnote[USBArmory MK II]],
        [6.638399], [Y],
      [ARM 64 bit AppliedMicro X-Gene Mustang Board], [5.599128], [Y],
      [Intel Atom Z530 – using #ac("GUI")], [3.38584], [Y],
      [Intel i7 7500U Skylake – 64-bit #ac("KVM") environment], [3.452064], [Y],
      [Intel i7 8565U Whiskey Lake – 64-bit #ac("KVM") environment], [7.400136],
        [Y],
      [Intel i7 8565U Whiskey Lake – 32-bit #ac("KVM") environment], [7.405704],
        [Y],
      [Intel i7 8565U Whiskey Lake], [6.871], [Y],
      [Intel Xeon E7 4870 8 sockets 160 #ac("CPU", pl: true) 8-way #ac("NUMA")],
      [7.287790], [Y], [Intel Xeon Gold 6234], [4.434168], [Y],
      [IBM POWER 8 LE 8286-42A], [6.830712], [Y],
      [IBM POWER 7 BE 8202-E4C], [4.233912], [Y],
      [IBM System Z z13 (machine 2964)], [4.366368], [Y],
      [IBM System Z z15 (machine 8561)], [5.691832], [Y],
      [MIPS Atheros AR7241 rev 1#footnote[Ubiquiti Nanostation M5 (xm)]],
        [7.157064], [Y],
      [MIPS Lantiq 34Kc V5.6#footnote[AVM Fritz Box 7490]], [7.032740], [Y],
      [Qualcomm IPQ4019 ARMv7#footnote[AVM Fritz Box 7520]], [6.638405],
        [Y],
      [SiFive HiFive Unmatched RISC-V U74], [2.387470], [Y],
    )
  },
  caption: [#ac("ESDM", cap: true) Entropy Testing Results on Different
  Hardware],
) <tab:measurements>

Some of the tested systems are old or small embedded devices. They
demonstrate that the #ac("ESDM") does not overestimate the available entropy
even on older and smaller systems under worst-case conditions.

The authors seek test data from all kinds of systems. The less
common a system is, the more its data help to verify that the basic
entropy estimate underlying the #ac("ESDM") is correct. Such data can be
generated with the #ac("ESDM") test tool set, specifically the test
documented in `tests/validation-helpers` and in section @sec:90b-reuse.

The Intel Atom Z530 in the table above demonstrates the effect of the
#ac("GCD"). The table shows its measurement without dividing the timestamps by
the #ac("GCD"). The #ac("GCD") measurement during boot detects that all
timestamps have a #ac("GCD") of 4, i.e. the low 2 bits are always unset.
Re-running
the entropy measurement on the timestamps divided by 4 yields an entropy rate
of 7.299 bits per 8 #ac("LSB") of the timestamp. After the division by the
#ac("GCD"), the 8 #ac("LSB") cover 2 additional bits, and these provide
additional entropy. This again demonstrates that the heuristic entropy
estimation of the #ac("ESDM") is safe. The 2 additional bits appear to provide
more than 2 bits of entropy: before the division by the #ac("GCD"), the measured
entropy rate was 3.38, so adding 2 bits with full entropy could raise the rate
to at most 5.38. This apparent inconsistency arises because a new test run
collected new entropy data. Network congestion may have affected the ping flood
that triggered the interrupts and added delays to them.

= Glossary <sec:glossary>

This glossary gives the terms as this document uses them. The document uses
the term of the standard it discusses, and #ac("DRNG") and entropy source for
the #ac("ESDM") itself.

/ Additional input: Data a #ac("DRBG") takes with a seed or generate request
  without credited entropy. The #ac("ESDM") passes the data of entropy sources
  credited with zero bits as additional input $U_n$ (section
  @sec:dp-seed-buffer).
/ Backtracking resistance: #ac("NIST"): the current state of a #ac("DRBG") does
  not reveal earlier output. #ac("AIS", cap: true) 20/31: enhanced backward
  secrecy.
/ Conditioning: A deterministic function that compresses entropy into a
  shorter bit string or distributes it. Internal when part of an entropy
  source (#ac("SP") 800-90B), external when the #ac("RBG") applies it to the
  output of its entropy sources (#ac("SP") 800-90C section 3.2).
  #ac("AIS", cap: true) 20/31: post-processing.
/ Credited entropy: The entropy the #ac("ESDM") counts for the data of an
  entropy source, given by its entropy rate (section @sec:physical-es).
/ DRBG, DRNG: Deterministic random bit generator (#ac("NIST")), deterministic
  random number generator (#ac("BSI")). This document uses #ac("DRBG") for the
  mechanisms of #ac("SP") 800-90A and #ac("DRNG") for the generators of the
  #ac("ESDM").
/ DRG.3, DRG.4, DRT.1, NTG.1, PTG.2, PTG.3: The functionality classes of
  #ac("AIS") 20/31 (section @sec:ais2031): #ac("DRNG", pl: true) with enhanced
  backward secrecy (DRG.3), with enhanced forward secrecy in addition
  (DRG.4), trees of #ac("DRNG", pl: true) (DRT.1), non-physical true
  #ac("RNG", pl: true) (NTG.1), physical true #ac("RNG", pl: true) (PTG.2)
  and those with cryptographic post-processing (PTG.3). Names of classes,
  not acronyms.
/ DRNG instance: A #ac("DRNG") with a state of its own: the initial #ac("DRNG"),
  the node #ac("DRNG", pl: true) and the #ac("DRNG") of the prediction
  resistance path (section @sec:numa).
/ DRNG tree: #ac("DRNG", pl: true) seeded by other #ac("DRNG", pl: true) from
  one initial randomness source: RBGC in #ac("SP") 800-90C, DRT.1 in #ac("AIS")
  20/31 (sections @sec:rbgc and @sec:drt1).
/ Entropy: Min-entropy in bits: $-log_2$ of the probability of the most
  likely value.
/ Entropy rate: Entropy per unit of data, e.g. bits per 256 bits of data for
  an entropy source of the #ac("ESDM"), or bits per timestamp.
/ Entropy source: #ac("NIST"): a noise source, its health tests and an optional
  conditioning component within one security boundary (#ac("SP") 800-90B). The
  #ac("ESDM") calls each source it seeds from an entropy source, e.g. the Jitter
  #acs("RNG").
/ Full entropy: #ac("NIST"): every bit holds at least $1 - epsilon$ bits of
  min-entropy, $epsilon <= 2^(-32)$. Output holds full entropy when at least
  64 bits more fresh entropy went in than comes out (#ac("SP") 800-90C section
  2.6 item 11).
/ Fully seeded: A #ac("DRNG") seeded with at least 256 bits of entropy, 384 bits
  for the initial seed with the #ac("SP") 800-90C oversampling (section
  @sec:seed-levels).
/ Health tests: Tests of the noise source output that detect its failure:
  the repetition count test, the adaptive proportion test and the start-up
  test of #ac("SP") 800-90B (section @sec:health-tests). #ac("AIS", cap: true)
  20/31: online tests and total failure test.
/ Initial randomness source: The randomness source of the root of a #ac("DRNG")
  tree, here the #ac("ESDM").
/ Method 1, Method 2: The two ways of #ac("SP") 800-90C section 2.3 to count
  entropy: of the physical entropy sources only, or of all entropy sources.
/ Noise source: The component whose behavior is the origin of the entropy,
  e.g. the timing of interrupts.
/ Non-physical entropy source: An entropy source whose noise source is
  system data or human interaction, e.g. event timing (#ac("SP") 800-90C section
  2.3, table @tab:physical-es). #ac("AIS", cap: true) 20/31: #ac("NPTRNG").
/ Operational: The #ac("ESDM") once its initial #ac("DRNG") is fully seeded and
  its self tests passed.
/ Oversampling: Requesting more entropy than the output needs: 64 bits per
  reseed and 128 bits for the initial seed with #ac("SP") 800-90C (section
  @sec:sp80090c), or #ac("OSR") timestamps per bit of entropy.
/ Path: One of the four ways the #ac("ESDM") serves output: full, plain,
  prediction resistance and seed (section @sec:interface-classes).
/ Physical entropy source: An entropy source whose noise source is dedicated
  hardware, e.g. ring oscillators (#ac("SP") 800-90C section 2.3).
  #ac("AIS", cap: true) 20/31: #ac("PTRNG").
/ Prediction resistance: #ac("NIST"): the #ac("DRBG") is reseeded with fresh
  entropy right before it generates output, so a compromised earlier state does
  not reveal it. #ac("AIS", cap: true) 20/31: enhanced forward secrecy.
/ Raw entropy: The unprocessed output of a noise source, e.g. time deltas,
  which the #ac("SP") 800-90B tools assess (section @sec:90b-reuse).
  #ac("AIS", cap: true) 20/31: raw random numbers.
/ RBG constructions: The constructions of #ac("SP") 800-90C. RBG1 is seeded once
  from another #ac("RBG"). RBG2 has an entropy source, physical (P) or
  non-physical (NP). RBG3 has physical entropy sources and full-entropy output,
  by #ac("XOR") with entropy source output (#ac("XOR")) or by a reseed before
  every output (RS). RBGC is a #ac("DRBG") of a #ac("DRNG") tree (sections
  @sec:90c-constructions and @sec:rbgc).
/ Reseed: Inserting fresh entropy into an instantiated #ac("DRBG").
/ Root: The first #ac("DRBG") of a #ac("DRNG") tree, seeded by the initial
  randomness source.
/ Security strength: The work in bits to break a mechanism; $s = 256$ bits
  for all #ac("DRNG", pl: true) of the #ac("ESDM").
/ Seed: Data with entropy that instantiates or reseeds a #ac("DRBG").
  #ac("SP", cap: true) 800-90C: seed material.
/ Start-up test: The health tests over the first 1,024 samples of an entropy
  source, before it delivers data (section @sec:health-tests).
/ Temporary seed buffer: The concatenated data of the entropy sources a
  #ac("DRNG") is seeded with, $T_n$ (section @sec:dp-seed-buffer).
/ Timestamp, time delta: The value of the high-resolution timer at an
  event, divided by the #ac("GCD"), and the difference of two timestamps
  (section @sec:dp-sched-irq).

#ac("NIST", cap: true) and the #ac("BSI") name the same concepts differently.
Table @tab:terminology pairs their terms as #ac("NIST") #ac("IR") 8446
@nistir8446 does.

#figure(
  table(columns: (1fr, 1fr, 1.3fr),
    table.header([#ac("SP", cap: true) 800-90 (#ac("NIST"))],
    [#ac("AIS", cap: true) 20/31 (#ac("BSI"))], [Meaning]),
    [#ac("DRBG", cap: true)], [#ac("DRNG", cap: true)], [Deterministic random
    number generator], [entropy source: noise source, health tests, optional
    conditioning],
      [noise source with its digitization; raw random numbers],
      [Where the entropy comes from],
    [conditioning], [post-processing],
      [Deterministic function that compresses or distributes entropy],
    [backtracking resistance], [enhanced backward secrecy],
      [The current state does not reveal earlier output],
    [prediction resistance], [enhanced forward secrecy],
      [After a reseed with fresh entropy, the earlier state does not
        reveal later output],
    [full entropy: at most $2^(-32)$ short of one bit per bit],
      [min-entropy of up to $1 - 2^(-32)$ per output bit (NTG.1, PTG.3)],
      [Output as unpredictable as ideal random bits],
    [RBG1], [DRG.3], [#ac("DRNG", cap: true) with enhanced backward secrecy; an
    RBG1 is
      seeded once from an external #ac("RBG")],
    [RBG2(P)], [DRG.4], [#ac("DRNG", cap: true) with a physical randomness
    source that can
      reseed on demand],
    [RBG2(NP)], [NTG.1], [#ac("DRNG", cap: true) with a non-physical randomness
    source;
      NTG.1 requires two noise sources at start-up],
    [RBGC, #ac("DRBG") tree], [DRT.1], [#ac("DRNG", pl: true, cap: true) seeded
    by #ac("DRNG", pl: true), from one initial
      randomness source],
    [RBG3(RS)], [PTG.3], [Output backed by fresh entropy throughout],
  ),
  caption: [#ac("NIST", cap: true) and #ac("BSI") terms],
) <tab:terminology>

= Acronyms <sec:acronyms>

This chapter lists the acronyms of the text and the figures. The text gives
the long form at the first use.

#acronym-index()

= Symbols <sec:symbols>

== Operators and Functions <sec:symbols-ops>

/ $x || y$: Concatenation of the bit strings $x$ and $y$
/ $|x|$: Length of $x$ in bits
/ $"MSB"_b (x)$: The $b$ most significant bits of $x$
/ $ceil(x)$, $floor(x)$: $x$ rounded up, rounded down
/ $"DRBG.Seed"(S, x)$: Seeds the #ac("DRBG") of state $S$ with $x$ (equation
  @eq:ep-cpu)
/ $"DRBG.Generate"(S, n, a)$: $n$ bits from the #ac("DRBG") of state $S$ with the
  additional input $a$ (equation @eq:ep-all)
/ $"XDRBG.Extract"(P, D, alpha)$: Reseeds the XDRBG-256 pool $P$ with the
  data $D$ and generates its output (section @sec:dp-aux)
/ $"SHAKE256"(x, l)$: $l$ bits of SHAKE256 output over $x$
/ $"SHA"(x)$: Message digest of $x$ (equation @eq:c-cond)
/ $"encode"(alpha, n)$: $alpha$ followed by the byte $85 n + |alpha|$
  (section @sec:dp-aux)
/ $italic("Output_Entropy")(n_"in", n_"out", italic("nw"), h_"in")$: The Output_Entropy function
  of #ac("SP") 800-90B section 3.1.5.1.2 (section @sec:90b-315)

== Seeding and Data Processing <sec:symbols-seeding>

/ $s$: Security strength of the #ac("DRNG", pl: true), 256 bits
/ $o$: Oversampling in bits: 64 for a reseed, 128 for the initial seed, one
  bit more in the kernel module (section @sec:dp-irq)
/ $"OSR"$: Oversampling rate, the timestamps credited with one bit of
  entropy; `ESDM_ES_OSR` in the kernel module (section @sec:dp-sched-irq)
/ $r$: Timestamps credited with 256 bits of entropy (section @sec:dp-irq)
/ $b$: Bits the #ac("ESDM") requests from an entropy source: 256, 320 or 384
  (section @sec:dp-irq)
/ $t$, $t_n$: Timestamp divided by the #ac("GCD") (section @sec:dp-sched-irq);
  in $T_n$, the current time
/ $d$: Time delta of an #acs("eBPF")-based entropy source (section @sec:dp-ebpf)
/ $"CP"_"CPU"$: Per-#acs("CPU") ring of timestamps (equation @eq:cp)
/ $"EP"_n$, $"SP"_n$: State of the #ac("DRBG") of the interrupt and of the
  scheduler entropy source after the $n$-th seed (equations @eq:ep-cpu and
  @eq:sp-cpu)
/ $B_n$: Output block of that #ac("DRBG") (equation @eq:ep-all)
/ $E_n$, $S_n$: Data of the interrupt and of the scheduler entropy source
  (equations @eq:e and @eq:s)
/ $E^"eBPF"_n$, $S^"eBPF"_n$: Data of the #acs("eBPF")-based interrupt and
  scheduler entropy sources (equation @eq:ebpf)
/ $J_n$, $C_n$, $K_n$, $H_n$, $M_n$, $J^"K"_n$, $X_n$, $A_n$: Data of the
  Jitter #acs("RNG"), the #ac("CPU"), the kernel #ac("RNG"), #ac("HWRAND"),
  #ac("TPM") 2.0, the kernel Jitter #acs("RNG"), the external entropy source and
  the auxiliary pool (equation @eq:t)
/ $T_n$: Temporary seed buffer of the $n$-th seeding (equation @eq:t)
/ $U_n$: Additional input of the $n$-th seeding (section
  @sec:dp-seed-buffer)
/ $"AP"$, $"XP"$: XDRBG-256 of the auxiliary pool and of the conditioning
  pool of an #acs("eBPF")-based entropy source (sections @sec:dp-aux and
  @sec:dp-ebpf)
/ $V_n$, $V'_n$: State of an XDRBG-256 after its reseed and after its
  extraction (equations @eq:ap and @eq:a)
/ $D_m$: Data inserted into the auxiliary pool (section @sec:dp-aux)
/ $alpha$: Additional input of an XDRBG-256 pool (section @sec:dp-aux); in
  the health tests, their significance level (section @sec:health-tests)
/ $m$: Data multiplier of the #ac("CPU") entropy source (section @sec:dp-cpu)
/ $r_C$: Entropy rate of the #ac("CPU") entropy source, bits per 256 bits of
  output (equation @eq:h-c)
/ $C_1, ..., C_k$, $C_"cond"$: Data of the #ac("CPU") entropy source and their
  digest (equation @eq:c-cond)

== Entropy Assessment <sec:symbols-entropy>

/ $H$: Min-entropy per sample as the #ac("SP") 800-90B tools estimate it,
  $min(H_"original", 8 dot H_"bitstring")$ (section @sec:90b-313)
/ $H_"original"$, $H_"bitstring"$: Estimates over the samples and over
  their bits (section @sec:90b-313)
/ $H_I$, $H_r$, $H_c$: Initial estimate and the estimates over the rows
  and the columns of the restart data (section @sec:90b-314)
/ $chi^2$: Chi-squared statistic, with its P value and degrees of freedom
  (section @sec:raw-distribution)
/ $h_t$: Entropy per timestamp, $1 \/ "OSR"$ (equation @eq:h-t)
/ $N$: Timestamps collected for one output block, $(256 + o) dot "OSR"$
  (section @sec:90b-3151)
/ $N_"CPU"$: Timestamps in the ring of a #ac("CPU") (section @sec:90b-3151)
/ $h_"CP"$: Entropy of these timestamps (equation @eq:h-cp)
/ $h_("DRBG"_n)$: Entropy in the state of the #ac("DRBG") after the $n$-th seed
  (equation @eq:h-pool)
/ $h_"aux pool"$: Entropy in the auxiliary pool (equation @eq:h-aux)
/ $h_B$: Entropy credited to an output block (equation @eq:h-hash-pools)
/ $h_s$: Entropy in the buffer of an entropy source (equation @eq:h-s)
/ $h_T$: Entropy of the temporary seed buffer (equation @eq:h-t-buffer)
/ $h_A, h_E, h_S, h_E^"eBPF", h_S^"eBPF", h_J, h_J^"K", h_C, h_K, h_H, h_M, h_X$: Entropy
  credited to the data of each entropy source (equation @eq:h-t-buffer)
/ $n_"in"$, $n_"out"$, $italic("nw")$, $h_"in"$, $h_"out"$: Input size,
  output size, narrowest internal width, input entropy and output entropy of
  a conditioning function (section @sec:90b-315)
/ $P_"high"$, $P_"low"$, $U$, $omega$: Intermediate values of the
  Output_Entropy function (section @sec:90b-315)

== SP 800-90C <sec:symbols-90c>

/ $3s \/ 2$: Entropy to instantiate a #ac("DRBG") of security strength $s$
  (section @sec:rbgc)
/ $s + 64$: Fresh entropy for $s$ bits of full-entropy output (section
  @sec:90c-constructions)
/ $"output_len"$: Output length of a conditioning function, which needs
  $"output_len" + 64$ bits of entropy for full-entropy output (section
  @sec:90c-config)
/ $epsilon$: Shortfall of full entropy from one bit per bit, at most
  $2^(-32)$ (section @sec:glossary)

= Bibliographic Reference <sec:bibliography>

#heading(level: 2, numbering: none, outlined: false)[References]
#bibliography("../references.bib", title: none, style: "../references.csl")

= License <sec:license>

The implementation of the Entropy Source and DRNG Manager, all support
mechanisms, the test cases and the documentation are subject to the following
license.

Copyright Stephan Müller \<smueller\@chronox.de\>, 2018–2026.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

+ Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

+ Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

+ The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

#par(first-line-indent: 0pt)[ALTERNATIVELY, this product may be distributed
under the terms of the GNU General Public License version 2, in which case the
provisions of the GPL are required INSTEAD OF the above restrictions. (This
clause is necessary due to a potential bad interaction between the GPL and the
restrictions contained in a BSD-style copyright.)]

THIS SOFTWARE IS PROVIDED “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE, ALL OF WHICH ARE HEREBY DISCLAIMED. IN NO
EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

The xoshiro256++ PRNG is derived from the code written in 2019 by David
Blackman and Sebastiano Vigna, who dedicated all copyright and related and
neighboring rights to it to the public domain worldwide.

= Change Log <sec:changelog>

The following table lists all released versions of the #ac("ESDM") with the main
changes of the #ac("ESDM") in each release – the file CHANGES.md of the source
code holds the complete list – and the changes of this document.

#{
  set par(justify: false, first-line-indent: 0pt, leading: 0.5em)
  set text(size: 9.5pt)
  set list(indent: 0pt, body-indent: 0.5em, spacing: 0.4em,
    marker: text(fill: accent)[•])
  show list: set block(above: 0.35em, below: 0.6em)
  // A version is not split across pages.
  set table.cell(breakable: false)
  // The kind of the changes that follow, in small capitals.
  let kind(name) = text(font: sans-font, size: 8pt, weight: "semibold",
    fill: muted, tracking: 0.08em, upper(name))
  // One row: version, release date, changes of the ESDM and of this document.
  let entry(version, date, esdm, doc: ()) = (
    text(font: sans-font, weight: "semibold", fill: accent, version),
    text(font: sans-font, fill: muted, date),
    {
      if esdm.len() > 0 {
        kind[#ac("ESDM", cap: true)]
        list(..esdm)
      }
      if doc.len() > 0 {
        kind[Document]
        list(..doc)
      }
    },
  )
  table(
    columns: (auto, auto, 1fr),
    inset: (x: 7pt, y: 6pt),
    align: left + top,
    // The release this document describes on a light tint.
    fill: (x, y) => if y == 0 { accent-light } else if y == 15 {
      surface-code },
    table.header([Version], [Date], [Changes]),
    ..entry([0.2.0], [2022-05-10], ([Initial public version],),
      doc: ([Initial public release],)),
    ..entry([0.3.0], [2022-06-10], (
      [Built-in #ac("RPC") mechanism replacing protobuf-c-rpc],
      [ChaCha20 #ac("DRNG") and SHA-3 conditioning hash],
      [`/proc/sys/kernel/random` files with SELinux policy],
    )),
    ..entry([0.4.0], [2022-07-02], (
      [Interrupt entropy source],
      [#ac("DRNG", cap: true) with prediction resistance for `/dev/random`
      opened with O\_SYNC], [Per-#acs("CPU") entropy pool of the scheduler
      entropy source], [#ac("CUSE", cap: true) daemons started independently of
      the #ac("ESDM") server],
    ), doc: (
      [Addition of new /proc interfaces],
      [Initial seeding is limited to availability of 256 bits],
      [Addition of interrupt #ac("ES") – addition of chapter 3 and appendix C],
      [NTG.1 compliance using `/dev/random` with O\_SYNC],
      [Per-#acs("CPU") scheduler entropy pool],
      [Correct various leftover statements from #ac("LRNG")],
    )),
    ..entry([0.5.0], [2022-08-13], (
      [Linux `/dev/hwrng` entropy source],
      [Access to the entropy sources with getrandom(2) and GRND\_SEED],
      [Separate #ac("DRNG") instance operated with prediction resistance],
    ), doc: (
      [Addition of #ac("HWRAND") entropy source],
      [Addition of GRND\_RANDOM to getrandom(2)],
      [Addition of GRND\_SEED to getrandom(2)],
    )),
    ..entry([0.6.0], [2023-06-26], (
      [#ac("AIS", cap: true) 20/31 (draft 2022) NTG.1 support],
      [#ac("ESDM", cap: true) applications confined to namespaces of their own],
      [Emergency seeding pulling repeatedly from the entropy sources],
      [`/dev/esdm_es` character device for the interrupt and scheduler
        entropy sources],
    ), doc: (
      [Addition of #ac("AIS") 20/31 (2022) support],
      [Add forced seeding operation discussion],
    )),
    ..entry([1.0.0], [2023-10-07], (
      [leancrypto, OpenSSL and Botan crypto backends],
      [Kernel Jitter #acs("RNG") entropy source],
      [Separate status of #ac("FIPS") 140 and #ac("SP") 800-90C compliance],
      [Build option oversample\_es renamed to sp80090c],
    ), doc: (
      [Rename oversample\_es],
      [Document #ac("FIPS") 140 mode],
    )),
    ..entry([1.0.1], [2023-11-24], (
      [Repeated initialization of #ac("RPC") client connections],
      [Fixes of the #ac("CUSE") daemons for poll and shutdown],
    )),
    ..entry([1.0.2], [2024-02-06], (
      [Hardening with -fzero-call-used-regs=used-gpr],
      [Faster #ac("RPC") communication],
      [Fixed shutdown sequence of the #ac("ESDM") daemons],
    ), doc: ([Update #ac("URL", pl: true) due to revamp of
    https://chronox.de],)), ..entry([1.1.0], [2024-03-23], (
      [#ac("ESDM", cap: true) auxiliary client library],
      [Connection to the server only established once and when needed],
    )),
    ..entry([1.1.1], [2024-07-27], (
      [Fixes of the timed mutex handling of the #ac("RPC") client library],
      [Fix of a race condition of the worker threads],
    )),
    ..entry([1.2.0], [2024-08-16], (
      [Only one prediction resistance or seed request in flight against
        denial of service over the #ac("RPC") channel],
      [CLOCK\_MONOTONIC for wait operations],
      [RPM spec file],
    )),
    ..entry([1.2.1], [2025-10-13], (
      [Kernel entropy sources with #ac("SP") 800-90A #ac("DRBG")
      post-processing,
        high-resolution timestamps only and an explicit oversampling rate],
      [#ac("AIS", cap: true) 20/31 DRG.4 compliance, NTG.1 updated to #ac("AIS")
      20/31 3.0], [Seeding of the kernel #ac("RNG") as application of its own],
      [Command line tool esdm-tool],
      [systemd notification and socket activation],
    )),
    ..entry([1.2.2], [2026-04-11], (
      [#ac("TPM", cap: true) 2.0 entropy source],
      [Multi-connection #ac("RPC") worker threads],
      [Backtracking resistance of the auxiliary pool],
      [Personalization string from the #ac("DMI") product #ac("UUID")],
      [64-bit timestamps and time deltas in the kernel entropy sources],
      [NTG.1 compliant jitterentropy library 3.7.0],
      [Minimally seeded stage removed],
    )),
    ..entry([1.2.3], [2026-05-02], (
      [#ac("DRNG", cap: true) with prediction resistance usable as RBG3(RS) in
      #ac("SP") 800-90C mode], [Prediction resistance requests over #ac("RPC")
      in chunks of 32 bytes], [Fixes of the #ac("CPU") entropy source fallback
      from RDSEED to RDRAND and of
        the #ac("SP") 800-90C instantiation with the OpenSSL backend],
    )),
    ..entry([1.2.4], [2026-11-14], (
      [Kernel module esdm\_es in `kernel/esdm_es`, conditioning with the
        XDRBG-256 on Linux 7.2 and later, state as #ac("JSON") only],
      [#acs("eBPF")-based scheduler and interrupt entropy sources],
      [External entropy sources served by provider processes, among them
        esdm-es-pkcs11 and esdm-es-pcsc],
      [#ac("EGD", cap: true) interface with a second socket for prediction
      resistance, #ac("EGD")
        client library, OpenSSL providers and the kernel module esdm\_cdev],
      [Auxiliary pool and #ac("eBPF") conditioning pool as XDRBG-256],
      [Build options ais2031\_ntg1, ais2031\_drg3 and ais2031\_drg4; Jitter
        #acs("RNG") in its NTG.1 mode seeds a #ac("DRNG") alone],
      [Self tests of the crypto implementations and of every entropy source
        repeated every 10 minutes and on demand; #ac("FIPS") 140 integrity test
        of the library],
      [Proactive reseeding of the #ac("DRNG", pl: true), #ac("DRNG") instances
      per #ac("RPC") worker], [#ac("TPM", cap: true) 2.0 and `/dev/hwrng`
      credited with no entropy by default], [Fuzz harnesses of the #ac("RPC")
      and #ac("EGD") interfaces],
    ), doc: (
      [Document translated to Typst, figures redrawn from draw.io and
        PlantUML sources],
      [Update to the code of #ac("ESDM") 1.2.4: design (chapter 2), interrupt
      and
        scheduler entropy sources of the kernel module esdm\_es assessed
        together, with #ac("DRBG") conditioning, oversampling, health test
        cutoffs and measurements in a #ac("KVM") guest (chapter 3)],
      [#ac("SP", cap: true) 800-90B assessment of the #acs("eBPF")-based
      scheduler and interrupt
        entropy sources with measurements in a #ac("KVM") guest: distribution,
        min-entropy and restart tests (chapter 4)],
      [Configurations of the new entropy sources, of #ac("AIS") 20/31 3.0 NTG.1,
        DRG.3 and DRG.4, and of the #ac("SP") 800-90C reseeding limits (chapter
        5)],
      [#ac("SP", cap: true) 800-90C analysis updated from the draft of 2021 to
      the final
        version of September 2025],
      [#ac("FIPS", cap: true) 140-2 #ac("IG") 7.18 analysis mapped to
      #ac("FIPS") 140-3 #ac("IG") D.J and D.K;
        bibliography with #ac("SP") 800-90A/C, #ac("AIS") 20/31, the #ac("FIPS")
        #ac("IG", pl: true) and the #ac("XDRBG")],
      [Change log listing all released versions],
    )),
  )
}
