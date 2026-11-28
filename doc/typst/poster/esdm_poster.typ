// A0 poster of the ESDM (portrait, 841 x 1189 mm) for open source
// conferences, workshops and office walls.
//
// What it has to achieve:
//   from 3 m    the ESDM is a random number generator for Linux in user
//               space: the title and the pipeline figure;
//   from 1.5 m  how entropy becomes random numbers, and that the ESDM is
//               tailored for FIPS 140-3 and AIS 20/31: the four stages and
//               the claims;
//   up close    enough detail to start a conversation, and the two links.
//
// It does not document the ESDM. All figures are drawn here for the poster,
// none is one of the design document: no label is smaller than 34 pt. The
// left column is the pipeline from the noise to the consumers; the right
// column, independent of it, says why to use the ESDM: eight claims, each a
// benefit in one line, then one deployment end to end - a guest of
// Cloud Hypervisor seeded through esdm_cdev - and the hardware
// and services that feed the ESDM through a provider process. Its statements are those of the design document,
// its colors those of palette.typ.

#import "../palette.typ": *
#import "../inputs.typ": esdm-version, doc-date
#import "../icons.typ": icon, brand

#let sans = "Source Sans 3"
#let mono = "Source Code Pro"
#let margin = 40mm
#let gutter = 26mm

#let t-body = 40pt
#let t-small = 34pt
#let t-stage = 54pt
#let t-heading = 76pt

#set document(title: [ESDM Poster],
  author: ("Stephan Müller", "Markus Theil"))
#set page(width: 841mm, height: 1189mm, margin: 0pt, fill: background)
#set text(font: sans, size: t-body, fill: ink, lang: "en",
  top-edge: "cap-height", bottom-edge: "baseline")
#set par(justify: false, leading: 0.62em, spacing: 0.9em)
#show raw: set text(font: mono, size: 1.12em)

// ---------------------------------------------------------------- elements

#let heading-text(body) = text(size: t-heading, weight: "semibold",
  fill: accent-text, tracking: -0.5pt, body)

// A rounded box with a label: an entropy source, a DRNG instance, an
// interface.
#let chip(body, fill: background, stroke: rule, color: ink, height: 42mm,
  weight: "regular") = box(width: 100%, height: height, radius: 5mm,
  fill: fill, stroke: 2.5pt + stroke, inset: (x: 3mm),
  align(center + horizon, text(fill: color, weight: weight, body)))

// The number of a stage.
#let badge(n) = box(width: 24mm, height: 24mm, radius: 12mm, fill: accent,
  align(center + horizon, text(size: 48pt, weight: "semibold",
    fill: background, str(n))))

// A stage of the pipeline: its number and name, what happens, the parts.
#let stage(n, title, note, body) = block(width: 100%, fill: surface,
  radius: 8mm, inset: 13mm, {
  grid(columns: (auto, 1fr), column-gutter: 8mm, align: horizon,
    badge(n),
    stack(spacing: 8mm,
      text(size: t-stage, weight: "semibold", title),
      text(size: t-small, fill: muted, note)))
  v(11mm, weak: true)
  body
})

// The arrow between two stages, with what happens on the way. It takes the
// height the grid of the pipeline leaves to its row.
#let flow-arrow(body) = block(width: 100%, height: 100%, inset: (y: 5mm),
  grid(columns: (1fr, 60pt, 1fr), rows: 100%, align: (left, center, left),
    [],
    grid(columns: 60pt, rows: (1fr, 44pt), align: center,
      rect(width: 12pt, height: 100%, fill: accent, stroke: none),
      polygon(fill: accent, stroke: none, (0pt, 0pt), (60pt, 0pt),
        (30pt, 44pt))),
    align(horizon, pad(left: 6mm, text(size: t-small, fill: muted, body)))))

#let chips(columns, ..items) = grid(columns: (1fr,) * columns,
  column-gutter: 7mm, row-gutter: 7mm, ..items)

// ---------------------------------------------------------------- header

#let header-h = 122mm
#let footer-h = 34mm

#block(width: 100%, height: header-h, fill: navy, inset: (x: margin),
  align(horizon, stack(spacing: 20mm,
    text(size: 116pt, weight: "semibold", fill: background,
      tracking: -1.5pt)[ESDM: Entropy Source and DRNG Manager],
    text(size: 50pt, fill: on-navy-soft)[Random numbers for Linux from
      user space – a toolkit for FIPS 140-3, SP 800-90 and AIS 20/31],
  )))

// ---------------------------------------------------------------- footer

#place(bottom, block(width: 100%, height: footer-h, fill: navy,
  inset: (x: margin), {
    set text(size: 30pt, fill: on-navy)
    align(horizon, grid(columns: (1fr, auto, auto), column-gutter: 28mm,
      text(weight: "semibold", tracking: 3pt,
        upper[ESDM #esdm-version · #doc-date]),
      [#box(baseline: 6pt, text(size: 44pt, icon("globe", fill: on-navy)))
        #h(0.4em) https://chronox.de/esdm/],
      [#box(baseline: 6pt, text(size: 40pt, brand("github"))) #h(0.4em)
        https://github.com/smuellerDD/esdm]))
  }))

// ---------------------------------------------------------------- pipeline

#let pipeline = grid(columns: 100%,
  rows: (auto, 14mm, auto, 1fr, auto, 1fr, auto, 1fr, auto),
  heading-text[From Noise to Random Numbers],
  [],
  stage(1)[Collect][Twelve entropy sources, each switched on, credited and
    reported on its own][
    #chips(4,
      chip(fill: source, stroke: source-strong)[Interrupts],
      chip(fill: source, stroke: source-strong)[Scheduler],
      chip[Jitter RNG],
      chip[CPU],
      chip[Kernel RNG],
      chip[TPM 2.0],
      chip[`/dev/hwrng`],
      chip[External],
    )
    #v(7mm, weak: true)
    #chip(fill: accent-faint, stroke: accent)[Auxiliary pool: data written
      by applications and by root]
  ],
  flow-arrow[Health tests on the raw \ data of the timing sources],
  stage(2)[Credit][Each source fills its slot of the seed buffer: data and
    the entropy it is credited][
    #let slot(fill, n) = stack(spacing: 4mm,
      rect(width: 100%, height: 36mm, fill: fill,
        stroke: 2.5pt + ink-soft),
      align(center, text(size: t-small, fill: muted, n)))
    #grid(columns: (1fr,) * 9, column-gutter: 0pt,
      slot(source)[256], slot(source-soft)[0], slot(accent-soft)[256],
      slot(accent-soft)[8], slot(accent-soft)[128], slot(background)[0],
      slot(background)[0], slot(background)[0], slot(accent-faint)[…])
  ],
  flow-arrow[Conditioned with a hash; \ the credits are added up],
  stage(3)[Seed][256 bits of entropy seed a DRNG instance fully, 384 bits
    with the SP 800-90C oversampling][
    #let drng(name, sub) = chip(fill: accent-soft, stroke: accent,
      height: 56mm, stack(spacing: 7mm,
        text(weight: "semibold", name),
        text(size: t-small, fill: muted, sub)))
    #grid(columns: (1fr, 1fr, auto, 1fr), column-gutter: 7mm,
      align: horizon,
      drng[DRNG][CPU 0], drng[DRNG][CPU 1],
      text(size: 60pt, fill: muted)[…],
      drng[DRNG][reseeded per block])
  ],
  flow-arrow[`esdm-server`, unprivileged \ after its start],
  stage(4)[Serve][Unmodified software, OpenSSL and hypervisors read from
    the interface they already use][
    #let face(body) = chip(fill: accent, stroke: accent, color: background,
      weight: "semibold", body)
    #chips(3,
      face[`/dev/random`], face[`getrandom()`], face[RPC library],
      face[EGD socket], face[OpenSSL provider], face[`/dev/esdm_pr`])
  ],
)

// ---------------------------------------------------------------- claims

#let claim(sign, title, body) = grid(columns: (27mm, 1fr),
  column-gutter: 9mm, align: horizon,
  box(width: 27mm, height: 27mm, radius: 6mm, fill: accent-soft,
    align(center + horizon, text(size: 54pt, icon(sign,
      fill: accent-text)))),
  stack(spacing: 6mm,
    text(size: 46pt, weight: "semibold", title),
    text(size: t-small, fill: muted, body)))

#let claims = {
  heading-text[Why the ESDM]
  v(14mm, weak: true)
  stack(spacing: 7mm,
    claim("plug")[Drop-in][No change to the applications],
    claim("microchip")[Stock kernel][No kernel patch; updated like any
      package],
    claim("puzzle")[A toolkit][Only the generator is mandatory],
    claim("scale")[Built for regulated use][FIPS 140-3, SP 800-90C,
      AIS 20/31],
    claim("key")[Keys from an assessed RNG][Key generation leaves the
      kernel RNG],
    claim("eye")[Every source accountable][Chosen, credited, tested and
      reported alone],
    claim("shield")[High assurance][Assessed, model checked, fuzzed],
    claim("lock")[Least privilege][Root for the set-up only, then dropped],
  )
}

// ---------------------------------------------------------------- example

// One deployment end to end: the ESDM of a host seeds a guest of Cloud
// Hypervisor through the kernel module esdm_cdev and virtio-rng.
#let example = {
  heading-text[Example: Entropy for a VM]
  v(14mm, weak: true)
  let part(title, sub, fill: background, stroke: rule) = chip(fill: fill,
    stroke: stroke, height: 33mm, stack(spacing: 5mm,
      text(weight: "semibold", title),
      text(size: t-small, fill: muted, sub)))
  let link(body) = grid(columns: (1fr, 40pt, 1fr), rows: 17mm,
    align: (left, center, left + horizon),
    [],
    grid(columns: 40pt, rows: (1fr, 30pt), align: center,
      rect(width: 9pt, height: 100%, fill: accent, stroke: none),
      polygon(fill: accent, stroke: none, (0pt, 0pt), (40pt, 0pt),
        (20pt, 30pt))),
    pad(left: 5mm, text(size: t-small, fill: muted, body)))
  let zone(name, fill, body) = block(width: 100%, fill: fill, radius: 8mm,
    inset: (x: 9mm, y: 7mm), {
    text(size: t-small, weight: "semibold", fill: muted, tracking: 2pt,
      upper(name))
    v(7mm, weak: true)
    body
  })
  zone([Host], surface, {
    part(fill: accent-soft, stroke: accent)[`esdm-server`][seeded by the
      entropy sources of the host]
    link[EGD socket]
    part[`esdm_cdev`: `/dev/esdm_pr`][kernel module, no fallback]
    link[read]
    part[Cloud Hypervisor][`--rng src=/dev/esdm_pr`]
  })
  link[virtio-rng]
  zone([Guest], accent-faint, {
    part(fill: accent-soft, stroke: accent)[ESDM of the guest][credits
      `/dev/hwrng` with 256 bits]
  })
}

// ---------------------------------------------------------------- devices

// Hardware and services as entropy sources: each is served by a provider
// process that the server reads as its external entropy source.
#let devices = {
  heading-text[HSM, Smart Card, KMS]
  v(14mm, weak: true)
  let part(title, sub, fill: background, stroke: rule, height: 33mm) = chip(
    fill: fill, stroke: stroke, height: height, stack(spacing: 5mm,
      text(weight: "semibold", title),
      if sub != none { text(size: t-small, fill: muted, sub) }))
  let down = align(center, grid(columns: 40pt, rows: (7mm, 30pt),
    align: center,
    rect(width: 9pt, height: 100%, fill: accent, stroke: none),
    polygon(fill: accent, stroke: none, (0pt, 0pt), (40pt, 0pt),
      (20pt, 30pt))))
  grid(columns: (1fr, 1fr, 1fr), column-gutter: 6mm, row-gutter: 4mm,
    part(fill: surface)[HSM][PKCS\#11],
    part(fill: surface)[Smart card][PC/SC],
    part(fill: surface)[KMS][KMIP, REST],
    down, down, down,
    grid.cell(colspan: 3, part[Provider process][`esdm-es-pkcs11`,
      `esdm-es-pcsc` or your own]),
    grid.cell(colspan: 3, down),
    grid.cell(colspan: 3, part(fill: accent-soft, stroke: accent)[
      `esdm-server`][external entropy source, credited as configured]),
  )
}

// ---------------------------------------------------------------- body

#let body-h = 1189mm - header-h - footer-h - 30mm - 36mm

#block(inset: (x: margin, y: 30mm), grid(columns: (1.22fr, 1fr),
  column-gutter: gutter,
  block(width: 100%, height: body-h, pipeline),
  block(width: 100%, height: body-h, {
    claims
    v(1fr)
    example
    v(1fr)
    devices
  }),
))
