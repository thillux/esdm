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
#import "../presentations/template.typ": hex-words

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
#let chip(body, fill: background, stroke: rule, color: ink, height: 45mm,
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

// A few points above a figure.
#let points(body) = {
  set text(size: t-small)
  set list(marker: text(fill: accent)[•], body-indent: 0.5em, spacing: 8mm)
  body
}

// A symbol, centred on its own bounds instead of the text line.
#let sign(name, size: 46pt, fill: accent-text) = text(size: size,
  top-edge: "bounds", bottom-edge: "bounds", icon(name, fill: fill))

// A part of a deployment: its symbol, its name and one line about it.
#let tile(name, title, sub, fill: background, stroke: rule,
  height: 31mm) = box(width: 100%, height: height, radius: 5mm, fill: fill,
  stroke: 2.5pt + stroke, inset: (x: 7mm), grid(columns: (17mm, 1fr),
    rows: 100%, column-gutter: 6mm, align: (center + horizon,
      left + horizon),
    sign(name),
    stack(spacing: 5mm,
      text(weight: "semibold", title),
      text(size: t-small, fill: muted, sub))))

// A card that holds the parts of one machine.
#let zone(name, fill, body) = block(width: 100%, fill: fill, radius: 8mm,
  inset: (x: 9mm, y: 8mm), {
  if name != none {
    text(size: t-small, weight: "semibold", fill: muted, tracking: 2pt,
      upper(name))
    v(7mm, weak: true)
  }
  body
})

// The arrow between two parts, with what connects them.
#let small-arrow(height: 15mm) = block(width: 40pt, height: height,
  grid(columns: 40pt, rows: (1fr, 24pt), align: center,
    rect(width: 9pt, height: 100%, fill: accent, stroke: none),
    polygon(fill: accent, stroke: none, (0pt, 0pt), (36pt, 0pt),
      (18pt, 24pt))))
#let link(body, height: 15mm) = grid(columns: (1fr, 40pt, 1fr),
  rows: height, align: (left, center, left + horizon),
  [], small-arrow(height: height),
  pad(left: 5mm, text(size: t-small, fill: muted, body)))

// Hex encoded random numbers as a texture: the words of the generator of
// the slides, each with a brightness of its own, faded by `fade(x, y)` with
// x and y from 0 to 1 across the field.
#let byte-field(width, height, size: 27pt, color: on-navy, fade: (x, y) => 1,
  strength: 0.3) = {
  let pitch-x = 3.1 * size
  let pitch-y = 1.55 * size
  let cols = calc.floor(width / pitch-x)
  let rows = calc.floor(height / pitch-y)
  let words = hex-words(cols * rows)
  box(width: width, height: height, {
    set text(font: mono, size: size)
    for r in range(rows) {
      for c in range(cols) {
        let (w, flicker) = words.at(r * cols + c)
        let alpha = calc.min(1, fade((c + 0.5) / cols, (r + 0.5) / rows)
          * (0.35 + 0.65 * flicker / 100) * strength)
        if alpha > 0.015 {
          place(top + left, dx: c * pitch-x, dy: r * pitch-y,
            text(fill: color.transparentize(100% * (1 - alpha)), w))
        }
      }
    }
  })
}

#let chips(columns, ..items) = grid(columns: (1fr,) * columns,
  column-gutter: 7mm, row-gutter: 7mm, ..items)

// ---------------------------------------------------------------- header

#let header-h = 118mm
#let footer-h = 34mm

// Navy, with random numbers fading in from the right behind the title.
#block(width: 100%, height: header-h, fill: navy, clip: true, {
  place(top + right, byte-field(440mm, header-h, strength: 0.34,
    fade: (x, y) => calc.pow(x, 1.7) * calc.pow(calc.sin(calc.pi * y),
      0.5)))
  block(width: 100%, height: 100%, inset: (x: margin),
    align(horizon, stack(spacing: 20mm,
      text(size: 116pt, weight: "semibold", fill: background,
        tracking: -1.5pt)[ESDM: Entropy Source and DRNG Manager],
      text(size: 50pt, fill: on-navy-soft)[Random numbers for Linux from
        user space – a toolkit for FIPS 140-3, SP 800-90 and AIS 20/31],
    )))
})

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
  rows: (auto, 14mm, auto, 1fr, auto, 1fr, auto, 1fr, auto, auto),
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
    #let slot(fill, name, n) = stack(spacing: 5mm,
      rect(width: 100%, height: 46mm, fill: fill,
        stroke: 2.5pt + ink-soft, align(center + horizon, name)),
      align(center, text(weight: "semibold", n)))
    #grid(columns: (1fr,) * 8, column-gutter: 0pt,
      slot(source)[IRQ][256], slot(source-soft)[Sched][0],
      slot(accent-soft)[Jitter][256], slot(accent-soft)[CPU][8],
      slot(accent-soft)[Kernel][128], slot(background)[TPM][0],
      slot(background)[hwrng][0], slot(accent-faint)[…][])
    #v(14mm, weak: true)
    #text(size: t-small, fill: muted)[Bits of entropy the default build
      credits to 256 bits of data of each source]
  ],
  flow-arrow[Conditioned with a hash; \ the credits are added up],
  stage(3)[Seed][256 bits of entropy seed a DRNG instance fully, 384 bits
    with the SP 800-90C oversampling][
    // Every instance is seeded from a seed buffer of its own collection.
    #let buffer = grid(columns: (1fr,) * 8, rows: 13mm,
      ..(source, source-soft, accent-soft, accent-soft, accent-soft,
        background, background, accent-faint).map(f => rect(width: 100%,
        height: 100%, fill: f, stroke: 2pt + ink-soft)))
    #let tip = align(center, polygon(fill: accent, stroke: none,
      (0pt, 0pt), (36pt, 0pt), (18pt, 26pt)))
    #let drng(name, sub) = stack(spacing: 4mm, buffer, tip,
      chip(fill: accent-soft, stroke: accent, height: 56mm,
        stack(spacing: 7mm,
          text(weight: "semibold", name),
          text(size: t-small, fill: muted, sub))))
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
      weight: "semibold", text(size: 37pt, body))
    #chips(3,
      face[`/dev/random`], face[`getrandom()`], face[RPC library],
      face[EGD socket], face[OpenSSL provider], face[`/dev/esdm_pr`])
  ],
  // What leaves the pipeline: random numbers, fading out downwards.
  {
    block(width: 100%, height: 30mm, flow-arrow[])
    layout(size => align(center, byte-field(size.width, 50mm, size: 31pt,
      color: accent-text, strength: 1.7,
      fade: (x, y) => calc.pow(1.1 - y, 1.3))))
  },
)

// ---------------------------------------------------------------- claims

#let claim(name, title, body) = grid(columns: (26mm, 1fr),
  column-gutter: 9mm, align: horizon,
  box(width: 26mm, height: 26mm, radius: 6mm, fill: accent,
    align(center + horizon, sign(name, size: 50pt, fill: background))),
  stack(spacing: 6mm,
    text(size: 46pt, weight: "semibold", title),
    text(size: t-small, fill: muted, body)))

#let claims = {
  heading-text[Why the ESDM]
  v(14mm, weak: true)
  stack(spacing: 6mm,
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
  points[
    - A guest has few events of its own: the host delivers its entropy.
    - With the Jitter RNG in its NTG.1 mode, the host seeds the guest
      with NTG.1 output; both then form one DRT.1 tree.
  ]
  v(10mm, weak: true)
  zone([Host], surface, {
    tile("server", fill: accent-soft, stroke: accent)[`esdm-server`][Jitter
      RNG in NTG.1 mode: `es_jent_ntg1`]
    link[EGD socket]
    tile("microchip")[`esdm_cdev`: `/dev/esdm_pr`][kernel module, no
      fallback]
    link[read]
    tile("cloud")[Cloud Hypervisor][`--rng src=/dev/esdm_pr`]
  })
  link[virtio-rng: NTG.1 seed]
  zone([Guest], accent-faint, {
    tile("cube", fill: accent-soft, stroke: accent)[ESDM of the guest][
      root of a DRT.1 tree, credits `/dev/hwrng`]
  })
}

// ---------------------------------------------------------------- devices

// Hardware and services as entropy sources: each is served by a provider
// process that the server reads as its external entropy source.
#let devices = {
  heading-text[Extensible Entropy Sources]
  v(14mm, weak: true)
  points[
    - An entropy source of your own is a small process built on
      `libesdm_es_ext`.
    - The providers for PKCS\#11 and PC/SC ship with the ESDM.
  ]
  v(10mm, weak: true)
  let device(name, title, sub) = chip(height: 33mm, stack(spacing: 5mm,
    [#box(baseline: 12%, sign(name, size: 36pt)) #h(0.2em)
      #text(weight: "semibold", title)],
    text(size: t-small, fill: muted, sub)))
  zone(none, surface, grid(columns: (1fr, 1fr, 1fr), column-gutter: 6mm,
    row-gutter: 3mm,
    device("key")[HSM][PKCS\#11],
    device("card")[Smart card][PC/SC],
    device("cloud")[KMS][KMIP, REST],
    ..(align(center, small-arrow(height: 12mm)),) * 3,
    grid.cell(colspan: 3, tile("plug")[Provider process][`esdm-es-pkcs11`,
      `esdm-es-pcsc` or your own]),
    grid.cell(colspan: 3, align(center, small-arrow(height: 12mm))),
    grid.cell(colspan: 3, tile("server", fill: accent-soft,
      stroke: accent)[`esdm-server`][external entropy source, credited as
      configured]),
  ))
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
