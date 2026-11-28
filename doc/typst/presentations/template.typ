// Slide template of the ESDM presentations.
//
// A 16:9 page of 793.7pt x 446.5pt in the visual language of the poster:
// Source Sans 3 in slate ink on white, one blue accent, a navy title slide
// and navy section dividers, a title that states the message of the slide
// above a short blue line, numbered steps, large numbers, cards, the figures
// of the design document, and dark terminal and editor cards in Source Code
// Pro.
//
// A slide is made for a projector: its text is set at 20pt (t-body) and not
// below 16pt (t-small); captions and the cells of the reference tables of the
// backup section use 13pt (t-caption), the windows 9pt or more. On a page
// 446pt high, 20pt is what 24pt is on the common 540pt slide.
//
// The footer of a slide names the sections of the deck with the current one
// highlighted, the deck and "n / N", above a line that fills with the
// progress through the deck. The sections and the slides are the bookmarks
// of the PDF.

// ---------------------------------------------------------------- colours

// ink: titles and body text, muted: secondary text, captions, faint: footer,
// hairline: card borders, table rules, accent: bullets, accent lines,
// accent-text: blue text on white, accent-soft: table header rows, navy:
// background of the title slide and the section dividers.
#import "../palette.typ": *
#import "../inputs.typ": esdm-version, doc-date
#import "../icons.typ": icon
#let hairline = line-color
#let link-blue = accent-text

// ---------------------------------------------------------------- fonts

#let sans = "Source Sans 3"
#let mono = "Source Code Pro"

#let t-body = 20pt
#let t-small = 16pt
#let t-caption = 13pt

// ---------------------------------------------------------------- geometry

#let page-width = 793.701pt
#let page-height = 446.457pt

// The body of a slide: below the title, above the footer, with the same
// margin left and right.
#let body-x = 40pt
#let body-top = 104pt
#let body-w = page-width - 2 * body-x
#let body-h = 304pt
#let gap = 28pt

#let figdir = "../figures/"

// What the footer of every slide names
#let deck-name = [Entropy Source and DRNG Manager]

// A term highlighted in the text, the same as *strong*
#let hl(body) = text(fill: accent-text, weight: "semibold", body)

// The names of the sections for the footer, and the number of the current
// one: 0 before the first section, one more than there are sections in the
// backup section.
#let deck-sections = state("esdm-deck-sections", ())
#let current-section = state("esdm-current-section", 0)
#let backup-name = [Backup]

// The bullets of the two list levels: a blue dot, a slate dash.
#let bullet = box(width: 0.5em, height: 0.5em, baseline: -0.08em,
  align(center + horizon, circle(radius: 0.15em, fill: accent, stroke: none)))
#let dash = text(fill: faint, "–")

#let setup(body, sections: ()) = {
  set document(author: "Stephan Müller")
  set page(width: page-width, height: page-height, margin: 0pt,
    fill: background)
  set text(font: sans, size: t-body, lang: "en", fill: ink, hyphenate: false)
  set par(leading: 0.5em, spacing: 0.85em, justify: false)
  set list(marker: (bullet, dash), indent: 0pt, body-indent: 0.5em,
    spacing: 0.85em)
  show strong: set text(weight: "semibold", fill: accent-text)
  show link: set text(fill: link-blue)
  // Raw text is set at 0.8em by default: the size of Source Code Pro beside
  // Source Sans 3. A name in the text is not broken across lines.
  show raw: set text(font: mono, size: 1em)
  show raw.where(block: false): box
  set table(stroke: 0.5pt + hairline,
    fill: (_, y) => if y == 0 { accent-soft })
  deck-sections.update(sections)
  body
}

// ---------------------------------------------------------------- frame

// A bookmark of the PDF: a heading that is laid out, but not shown.
#let bookmark(level, body) = place(top + left, hide(box(width: 600pt,
  height: 0pt, clip: true, heading(level: level, body))))

// The footer: the sections with the current one highlighted on the left,
// the deck and "n / N" on the right, and the progress line at the bottom
// edge.
#let footer = context {
  let n = counter(page).get().first()
  let total = counter(page).final().first()
  let secs = deck-sections.get()
  let cur = current-section.get()
  set text(size: 9pt, fill: muted, top-edge: "cap-height",
    bottom-edge: "baseline")
  place(top + left, dx: body-x, dy: 427pt, {
    let names = secs + (backup-name,)
    for (i, s) in names.enumerate() {
      if i > 0 { h(10pt) }
      if i + 1 == cur {
        text(fill: accent-text, weight: "semibold", s)
      } else { s }
    }
  })
  place(top + right, dx: -body-x, dy: 427pt,
    [#deck-name #h(10pt) #n / #total])
  place(bottom + left, rect(width: page-width, height: 2.5pt,
    fill: line-color, stroke: none))
  place(bottom + left, rect(width: page-width * n / total, height: 2.5pt,
    fill: accent, stroke: none))
}

// Title of a content slide: semibold, left aligned, one or two lines ending
// on the same baseline, with a short blue line below it.
#let slide-title(title) = {
  place(top + left, dx: body-x, dy: 18pt,
    box(width: body-w, height: 60pt, align(left + bottom, {
      set text(size: 26pt, weight: "semibold", fill: ink,
        top-edge: "cap-height", bottom-edge: "baseline", tracking: -0.2pt)
      set par(leading: 0.34em)
      title
    })))
  place(top + left, dx: body-x, dy: 87pt,
    rect(width: 40pt, height: 3pt, radius: 1.5pt, fill: accent, stroke: none))
}

// A content slide: the title states its message, the body holds a few
// points or a figure with callouts. `valign` aligns the body in its area.
#let slide(title: none, valign: top, body) = {
  if title != none {
    bookmark(2, title)
    slide-title(title)
  }
  place(top + left, dx: body-x, dy: body-top, block(width: body-w,
    height: body-h, align(valign, body)))
  footer
  pagebreak(weak: true)
}

// ---------------------------------------------------------------- elements

// Two or more columns filling the body; `widths` are the column widths.
#let cols(widths: (1fr, 1fr), gutter: gap, valign: top, ..children) = grid(
  columns: widths, column-gutter: gutter, align: valign, ..children)

// A figure of the design document, by its file name in figures/, scaled
// into the width of its container and `height`.
#let pic(file, height: body-h, align: center + horizon) = layout(size => {
  let natural = measure(image(figdir + file))
  let s = calc.min(size.width / natural.width, height / natural.height)
  box(width: size.width, height: height, std.align(align,
    image(figdir + file, width: natural.width * s)))
})

// A number with what it counts.
#let stat(number, label) = stack(spacing: 10pt,
  text(size: 46pt, weight: "semibold", fill: accent-text, tracking: -1pt,
    top-edge: "cap-height", bottom-edge: "baseline", number),
  text(size: t-small, fill: muted, label))

// A numbered step: a number in a blue circle, a title, a short text.
#let step(n, title, body) = grid(columns: (30pt, 1fr), column-gutter: 12pt,
  box(width: 30pt, height: 30pt, radius: 15pt, fill: accent,
    align(center + horizon, text(size: 17pt, weight: "semibold",
      fill: background, top-edge: "cap-height", bottom-edge: "baseline",
      str(n)))),
  {
    v(7pt)
    text(weight: "semibold", title)
    v(9pt, weak: true)
    set text(size: t-small, fill: ink-soft)
    set par(leading: 0.45em)
    body
  })

// A card: a title in blue over a short text, on a light surface.
#let card(title, body, fill: surface, height: auto, size: t-small) = block(
  width: 100%, height: height, fill: fill, radius: 6pt,
  inset: (x: 14pt, y: 13pt), {
    set text(size: size)
    set par(leading: 0.45em, spacing: 0.7em)
    set list(spacing: 0.7em)
    if title != none {
      block(below: 13pt, text(weight: "semibold", fill: accent-text, title))
    }
    body
  })

// A note that must not be missed: a sign on a light blue card.
#let note(body, sign: "warning") = block(width: 100%, fill: accent-faint,
  radius: 6pt, inset: (x: 14pt, y: 11pt), grid(columns: (auto, 1fr),
    column-gutter: 10pt, icon(sign, fill: source-strong), {
      set text(size: t-small)
      set par(leading: 0.45em)
      body
    }))

// Where the design document says more: a line at the bottom of the body.
#let more(body) = place(bottom + left, text(size: t-caption, fill: muted,
  [Design document: #body]))

// A reference table of the backup section: small text, a blue header row.
#let ref-table(columns: auto, size: t-caption, align: left + horizon,
    inset: (x: 7pt, y: 5.5pt), ..cells) = {
  set text(size: size, top-edge: "cap-height", bottom-edge: "baseline")
  set par(leading: 0.45em)
  show table.cell.where(y: 0): set text(weight: "semibold",
    fill: accent-text)
  table(columns: columns, align: align, inset: inset, ..cells)
}

// ---------------------------------------------------------------- title

// xoshiro256++ (Blackman/Vigna) for the random numbers of the title slide,
// on Typst's signed 64 bit integers, which hold the bit patterns of the
// unsigned words: shifts and the bitwise operations act on the bits, only the
// addition has to wrap by hand. A fixed seed makes every build the same, so
// the PDF stays reproducible.
#let m32 = 0xffffffff
// A 64 bit word from its upper and lower 32 bits.
#let u64(hi, lo) = hi.bit-lshift(32).bit-or(lo)
// a + b mod 2^64, in 32 bit halves: Typst errors on an overflowing +.
#let add64(a, b) = {
  let lo = a.bit-and(m32) + b.bit-and(m32)
  let hi = (a.bit-rshift(32, logical: true) + b.bit-rshift(32, logical: true)
    + lo.bit-rshift(32, logical: true))
  u64(hi.bit-and(m32), lo.bit-and(m32))
}
#let rotl(x, k) = x.bit-lshift(k).bit-or(x.bit-rshift(64 - k, logical: true))
// One step of the generator: (output, next state).
#let xoshiro-next(s) = {
  let (s0, s1, s2, s3) = s
  let out = add64(rotl(add64(s0, s3), 23), s0)
  let t = s1.bit-lshift(17)
  s2 = s2.bit-xor(s0)
  s3 = s3.bit-xor(s1)
  s1 = s1.bit-xor(s2)
  s0 = s0.bit-xor(s3)
  s2 = s2.bit-xor(t)
  s3 = rotl(s3, 45)
  (out, (s0, s1, s2, s3))
}
// The state SplitMix64 expands the seed 20261123 into, as the authors of
// xoshiro recommend for seeding it. Its first outputs are f553f7f36fdb85c5,
// 9b48a1626a34bb9f, ea0123e00d515e00 and 75a6707905561b0a.
#let xoshiro-seed = (u64(0xb846dce5, 0x05e9bf91), u64(0xc326f6f9, 0xc7f7f463),
  u64(0x2ec4e27b, 0xe3115621), u64(0x2b458b95, 0x144c5d42))

// n 16 bit words of the generator as 4 hex digits each, every one with a
// brightness of 0 to 99 from the next 16 bit word.
#let hex-words(n) = {
  let s = xoshiro-seed
  let bits = ()
  while bits.len() < 2 * n {
    let (out, next) = xoshiro-next(s)
    s = next
    for i in range(4) {
      bits.push(out.bit-rshift(48 - 16 * i, logical: true).bit-and(0xffff))
    }
  }
  range(n).map(i => {
    let w = str(bits.at(2 * i), base: 16)
    ("0" * (4 - w.len()) + w, calc.rem(bits.at(2 * i + 1), 100))
  })
}

// A field of hex encoded random numbers on the right of the title slide and
// of the section dividers, fading out towards the title and the top and
// bottom edges: faint at the right edge, gone where the text begins, every
// word with a little flicker of its own.
#let random-field = {
  let (cols, rows) = (13, 27)
  let (x0, y0, pitch-x, pitch-y) = (360pt, 14pt, 33pt, 16pt)
  let words = hex-words(cols * rows)
  set text(font: mono, size: 10.5pt)
  for r in range(rows) {
    for c in range(cols) {
      let (w, flicker) = words.at(r * cols + c)
      let x = x0 + c * pitch-x
      // 0 at the left end of the field, 1 at the right edge of the slide
      let f = calc.max(0, (x - x0) / (page-width - x0 - pitch-x))
      // and softly towards the top and the bottom edge
      let v = calc.sin(calc.pi * (r + 0.5) / rows)
      let alpha = (calc.pow(f, 1.8) * calc.pow(v, 0.6)
        * (0.4 + 0.6 * flicker / 100) * 0.22)
      if alpha > 0.02 {
        place(top + left, dx: x, dy: y0 + r * pitch-y,
          text(fill: on-navy.transparentize(100% * (1 - alpha)), w))
      }
    }
  }
}

// The title slide: deep navy, a blue line above the large white title, the
// subtitle and the version in blue, the author in light slate, and hex
// encoded random numbers fading in on the right.
#let title-slide(title: none, author: none, subtitle: none,
    version: none) = {
  place(top + left, rect(width: page-width, height: page-height,
    fill: navy, stroke: none))
  random-field
  place(top + left, dx: body-x + 8pt, dy: 92pt,
    rect(width: 56pt, height: 4pt, radius: 2pt, fill: accent, stroke: none))
  place(top + left, dx: body-x + 8pt, dy: 112pt, block(width: 640pt, {
    set text(top-edge: "cap-height", bottom-edge: "baseline")
    set par(leading: 0.36em)
    text(size: 42pt, weight: "semibold", fill: background, tracking: -0.4pt,
      title)
    if subtitle != none {
      v(18pt)
      text(size: 21pt, fill: on-navy-soft, subtitle)
    }
  }))
  place(top + left, dx: body-x + 8pt, dy: 318pt, block(width: 420pt, {
    set text(top-edge: "cap-height", bottom-edge: "baseline")
    set par(leading: 0.55em)
    if version != none {
      text(size: 12pt, weight: "semibold", fill: on-navy,
        tracking: 1.2pt, upper(version))
      v(14pt)
    }
    text(size: 17pt, fill: rule, author)
  }))
  pagebreak(weak: true)
}

// A section divider in the colours of the title slide: the number of the
// section, its title and what it covers. It makes the section the current
// one of the footer. Without a `number` it starts the backup section.
#let section-slide(number: none, title: none, subtitle: none) = {
  context current-section.update(if number == none {
    deck-sections.get().len() + 1
  } else { number })
  bookmark(1, title)
  place(top + left, rect(width: page-width, height: page-height,
    fill: navy, stroke: none))
  random-field
  place(top + left, dx: body-x + 8pt, dy: 132pt,
    rect(width: 56pt, height: 4pt, radius: 2pt, fill: accent, stroke: none))
  place(top + left, dx: body-x + 8pt, dy: 154pt, block(width: 600pt, {
    set text(top-edge: "cap-height", bottom-edge: "baseline")
    set par(leading: 0.36em)
    text(size: 12pt, weight: "semibold", fill: on-navy, tracking: 1.2pt,
      context if number == none { upper(backup-name) } else {
        [PART #number OF #deck-sections.get().len()]
      })
    v(20pt)
    text(size: 40pt, weight: "semibold", fill: background, tracking: -0.4pt,
      title)
    if subtitle != none {
      v(20pt)
      text(size: 20pt, fill: on-navy-soft, subtitle)
    }
  }))
  pagebreak(weak: true)
}

// ---------------------------------------------------------------- windows

// The palette of the terminal and editor cards: code of palette.typ.

// Height of the title bar above the text area of a window
#let window-bar = 14pt

// The height of the text area of a window that shows n lines.
#let window-height(n, size: 9pt, inset-y: 7pt) = (n * 1.36 * size
  + 2 * inset-y)

// A dark card as wide as its container: a slim title bar with three dots
// (and an optional title) above a text area of `height` (by default the
// one of its lines), which holds `lines` in Source Code Pro of `size` with a
// line pitch of 1.36 `size`. Every line is a string (shown verbatim, styled
// by the regex `rules` given as (regex, function) pairs) or content. A line
// longer than the window is cut off at its edge.
#let window(lines, height: none, size: 9pt, rules: (), inset-x: 9pt,
    inset-y: 7pt, title: none) = layout(avail => {
  let pitch = 1.36 * size
  let w = avail.width
  let h = if height == none {
    window-height(lines.len(), size: size, inset-y: inset-y)
  } else { height }
  block(width: w, height: h + window-bar, fill: code.bg, radius: 6pt,
    clip: true, stroke: 0.6pt + code.border, {
      place(top + left, rect(width: 100%, height: window-bar,
        fill: code.bar, stroke: none))
      for i in range(3) {
        place(top + left, dx: 8pt + i * 8.5pt, dy: window-bar / 2 - 2.5pt,
          circle(radius: 2.5pt, fill: code.dot, stroke: none))
      }
      if title != none {
        place(top + left, box(width: w, height: window-bar,
          align(center + horizon, text(font: mono, size: 7.5pt,
            fill: code.title, top-edge: "cap-height",
            bottom-edge: "baseline", title))))
      }
      place(top + left, dy: window-bar, block(width: w, height: h,
        inset: (left: inset-x, top: inset-y), {
          set align(left)
          set text(font: mono, size: size, fill: code.fg,
            top-edge: 0.928em, bottom-edge: -0.236em, hyphenate: false)
          show raw: set text(font: mono, size: size)
          set raw(tab-size: 8)
          show: body => rules.fold(body, (b, r) => {
            show r.at(0): r.at(1)
            b
          })
          for l in lines {
            block(height: pitch, above: 0pt, below: 0pt, width: 10 * w,
              if type(l) == str { raw(l) } else { l })
          }
        }))
    })
})

// An editor window showing lines of meson_options.txt: comments slate, the
// option keyword blue, strings - the ''' descriptions included - green.
// `lines` are the verbatim lines of the file.
#let meson-view(lines, height: none, size: 9pt,
    title: "meson_options.txt") = {
  let str-col(s) = text(fill: code.string, raw(s))
  // A line outside of a description: quoted strings coloured, the rest plain.
  let plain(s) = {
    let parts = ()
    let pos = 0
    for m in s.matches(regex("'[^']*'")) {
      parts.push(raw(s.slice(pos, m.start)))
      parts.push(str-col(m.text))
      pos = m.end
    }
    parts.push(raw(s.slice(pos)))
    parts.join()
  }
  let out = ()
  let in-str = false
  for l in lines {
    if in-str {
      let i = l.position("'''")
      if i == none {
        out.push(str-col(l))
      } else {
        out.push([#str-col(l.slice(0, i + 3))#raw(l.slice(i + 3))])
        in-str = false
      }
    } else if l.trim().starts-with("#") {
      out.push(text(fill: code.comment, raw(l)))
    } else {
      let i = l.position("'''")
      let head = if i == none { l } else { l.slice(0, i) }
      let lead = head.len() - head.trim(at: start).len()
      let body = if head.trim().starts-with("option") {
        [#raw(head.slice(0, lead))#text(fill: code.keyword,
          weight: "bold", raw("option"))#plain(head.slice(lead + 6))]
      } else { plain(head) }
      if i != none {
        let rest = l.slice(i + 3)
        let j = rest.position("'''")
        if j == none {
          body = [#body#str-col(l.slice(i))]
          in-str = true
        } else {
          body = [#body#str-col(l.slice(i, i + 3 + j + 3))#raw(rest.slice(j + 3))]
        }
      }
      out.push(body)
    }
  }
  window(out, height: height, size: size, title: title)
}
