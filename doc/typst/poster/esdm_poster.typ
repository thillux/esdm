// A0 poster of the ESDM (portrait, 841 x 1189 mm) for open source
// conferences, workshops and office walls.
//
// What it has to achieve:
//   from 3 m    the ESDM is a random number generator for Linux in user
//               space: the title and the pipeline figure;
//   from 1.5 m  how entropy becomes random numbers, and that the ESDM is
//               tailored for FIPS 140-3 and AIS 20/31: the four stages and
//               the four claims;
//   up close    enough detail to start a conversation, and the two links.
//
// It does not document the ESDM. All figures are drawn here for the poster,
// none is one of the design document: no label is smaller than 34 pt. The
// left column is the pipeline from the noise to the consumers; the right
// column, independent of it, shows the seed buffer, the states of a DRNG
// instance and the claims. Its statements are those of the design document,
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

// ---------------------------------------------------------------- seed buffer

// The slots of the seed buffer: every source delivers 256 bits of data, the
// bar is the entropy the default build credits them.
#let seed-buffer = {
  heading-text[Seed Buffer]
  v(14mm, weak: true)
  let row(name, bits, fill: accent) = (
    align(horizon, name),
    box(width: 100%, height: 24mm, fill: surface, radius: 2mm,
      stroke: 2pt + rule, align(left, rect(width: calc.max(bits / 256, 0.012)
        * 100%, height: 100%, radius: 2mm, fill: fill, stroke: none))),
    align(horizon + right, text(weight: "semibold", str(bits))),
  )
  grid(columns: (auto, 1fr, 26mm), column-gutter: 8mm, row-gutter: 8mm,
    ..row([Interrupts], 256, fill: source-strong),
    ..row([Jitter RNG], 256),
    ..row([Kernel RNG], 128),
    ..row([CPU], 8),
    ..row([TPM 2.0], 0),
  )
  v(10mm, weak: true)
  text(size: t-small, fill: muted)[Bits of entropy the default build
    credits to 256 bits of data. The credits are added up; data without
    credit still goes into the seed.]
}

// ---------------------------------------------------------------- states

// The states of a DRNG instance, drawn on a canvas of fixed size.
#let states = {
  heading-text[DRNG Instance]
  v(14mm, weak: true)
  let w = 320mm // canvas
  let node-x = 30mm
  let node-w = 200mm
  let node-h = 56mm
  let gap = 72mm
  let y(i) = i * (node-h + gap)
  let at(dx, dy, body) = place(top + left, dx: dx, dy: dy, body)
  let node(i, title, sub, fill: accent-soft, stroke: accent) = at(node-x,
    y(i), box(width: node-w, height: node-h, radius: 8mm, fill: fill,
      stroke: 2.5pt + stroke, align(center + horizon, stack(spacing: 7mm,
        text(weight: "semibold", title),
        text(size: t-small, fill: muted, sub)))))
  let seg(x1, y1, x2, y2, stroke) = at(x1, y1, line(start: (0pt, 0pt),
    end: (x2 - x1, y2 - y1), stroke: stroke))
  // An arrow head at (x, y) pointing down, up or right.
  let head(x, y, dir, fill) = at(x, y, {
    let a = 9mm
    let b = 5mm
    polygon(fill: fill, stroke: none, ..if dir == "down" {
      ((-b, -a), (b, -a), (0mm, 0mm))
    } else if dir == "up" {
      ((-b, a), (b, a), (0mm, 0mm))
    } else { ((-a, -b), (-a, b), (0mm, 0mm)) })
  })
  let ok = 5pt + accent
  let bad = (paint: alert, thickness: 5pt, dash: (14pt, 10pt))
  let label(x, y, body, fill: muted) = at(x, y, box(width: 120mm,
    text(size: t-small, fill: fill, body)))
  let down-x = node-x + 40mm
  let up-x = node-x + node-w - 40mm
  let fail-x = 6mm

  box(width: w, height: y(2) + node-h, {
    node(0, fill: surface, stroke: ink-soft)[Not fully seeded][no output]
    node(1)[Fully seeded][serves requests]
    node(2)[Reseed due][reseeds, then serves]
    // seeded
    seg(down-x, y(0) + node-h, down-x, y(1) - 8mm, ok)
    head(down-x, y(1), "down", accent)
    label(down-x + 9mm, y(0) + node-h + 30mm)[256 bits of entropy]
    // reseed due
    seg(down-x, y(1) + node-h, down-x, y(2) - 8mm, ok)
    head(down-x, y(2), "down", accent)
    at(down-x + 7mm, y(1) + node-h + 21mm, box(width: up-x - down-x
      - 14mm, align(center, text(size: t-small, fill: muted)[2#super[20]
        requests \ or 600 s])))
    // reseeded
    seg(up-x, y(2), up-x, y(1) + node-h + 8mm, ok)
    head(up-x, y(1) + node-h, "up", accent)
    label(up-x + 9mm, y(1) + node-h + 30mm)[full reseed]
    // the state is lost
    seg(node-x, y(1) + node-h / 2, fail-x, y(1) + node-h / 2, bad)
    seg(node-x, y(2) + node-h / 2, fail-x, y(2) + node-h / 2, bad)
    seg(fail-x, y(2) + node-h / 2, fail-x, y(0) + node-h / 2, bad)
    seg(fail-x, y(0) + node-h / 2, node-x - 8mm, y(0) + node-h / 2, bad)
    head(node-x, y(0) + node-h / 2, "right", alert)
  })
  v(10mm, weak: true)
  text(size: t-small, fill: alert)[Dashed: a reset, a fork in the child,
    or 2#super[30] requests without a full reseed.]
}

// ---------------------------------------------------------------- claims

#let claim(sign, title, body) = grid(columns: (32mm, 1fr),
  column-gutter: 9mm, align: horizon,
  box(width: 32mm, height: 32mm, radius: 7mm, fill: accent-soft,
    align(center + horizon, text(size: 64pt, icon(sign,
      fill: accent-text)))),
  stack(spacing: 6mm,
    text(size: 46pt, weight: "semibold", title),
    text(size: t-small, fill: muted, body)))

#let claims = {
  heading-text[Why the ESDM]
  v(14mm, weak: true)
  stack(spacing: 13mm,
    claim("plug")[A toolkit][Only the generator is mandatory. Sources,
      interfaces and kernel modules are chosen per system.],
    claim("shield")[Built for regulated use][Configurations for
      SP 800-90C, FIPS 140-3 and AIS 20/31: NTG.1, DRG.3, DRG.4.],
    claim("key")[Keys outside the kernel][Keys are generated in user
      space; the kernel RNG is seeded by the ESDM.],
    claim("flask")[Assured][SP 800-90B assessment, health and self tests,
      model checking, fuzzing.],
  )
}

// ---------------------------------------------------------------- body

#let body-h = 1189mm - header-h - footer-h - 30mm - 36mm

#block(inset: (x: margin, y: 30mm), grid(columns: (1.22fr, 1fr),
  column-gutter: gutter,
  block(width: 100%, height: body-h, pipeline),
  block(width: 100%, height: body-h, {
    seed-buffer
    v(1fr)
    states
    v(1fr)
    claims
  }),
))
