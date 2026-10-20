// Slide template of the ESDM presentations.
//
// A 16:9 page of 793.7pt x 446.5pt in Liberation Sans - the page and the text
// area of the LibreOffice Impress master of the original decks, so that the
// figures and windows placed on a slide stay where they are -, with a light
// frame: a slim red strip along the top, slide titles in bold dark ink beside
// a red bar, and a footer of a hairline, the name of the deck and the slide
// number. The outline bullets are a red square (level 1), a grey en dash
// (level 2) and a grey ring (level 3). Impress shrinks the outline text of a
// slide until it fits; the shrink factor of every slide is given as `scale`
// (1 = 32pt level-1 text).

#let red = rgb(199, 36, 58)
#let ink = rgb(31, 41, 51)
#let muted = rgb(107, 114, 128)
#let hairline = rgb(209, 213, 219)
#let link-blue = rgb(37, 99, 235)

#let page-width = 793.701pt
#let page-height = 446.457pt

// Left edge of the outline text box and top of its first line.
#let body-x = 39.7pt
#let body-top = 130pt

// What the footer of every slide names
#let deck-name = [Entropy Source and DRNG Manager]

// The red strip along the top of every slide
#let top-strip = place(top + left,
  rect(width: 100%, height: 4pt, fill: red, stroke: none))

// The footer: a hairline across the text area, the name of the deck on the
// left and the slide number on the right, both in grey.
#let footer(number) = {
  place(top + left, dx: body-x, dy: 426pt,
    line(length: page-width - 2 * body-x, stroke: 0.5pt + hairline))
  place(top + left, dx: body-x, dy: 431pt,
    text(size: 10pt, fill: muted, deck-name))
  if number != none {
    place(top + right, dx: -body-x, dy: 431pt,
      text(size: 10pt, fill: muted, weight: "bold", str(number)))
  }
}

// Impress lays out text with the hhea metrics of Liberation Sans (ascender
// 0.905em, descender 0.212em, no line gap); Typst defaults to the smaller
// OS/2 typo metrics, so the edges are set explicitly everywhere.
#let setup(body) = {
  set document(author: "Stephan Müller")
  set page(width: page-width, height: page-height, margin: 0pt,
    fill: white)
  set text(font: "Liberation Sans", size: 18pt, lang: "en", fill: ink,
    top-edge: 0.905em, bottom-edge: -0.212em)
  set par(leading: 0pt, spacing: 0pt, justify: false)
  body
}

// A title beside a red bar as high as it is.
#let barred(title, size, bar) = grid(columns: (bar, auto),
  column-gutter: 2.5 * bar,
  grid.cell(fill: red, []),
  text(size: size, weight: "bold", fill: ink, title))

// Title of a content slide: 34pt, vertically centred on y = 81.8pt.
#let slide-title(title) = place(top + left, dx: body-x, dy: 21.8pt,
  box(height: 120pt, width: page-width - body-x - 10pt,
    align(left + horizon, barred(title, 34pt, 5pt))))

// Outline levels: text size, indent of the bullet and the text, space after
// the paragraph (all for scale 1, as factors of the 32pt level-1 size).
#let levels = (
  (size: 32pt, marker-x: 8.6pt, text-x: 33.9pt, below: 14.2pt),
  (size: 28pt, marker-x: 42.6pt, text-x: 68.2pt, below: 11.5pt),
  (size: 24pt, marker-x: 79.0pt, text-x: 101.8pt, below: 8.3pt),
)

// The bullet of an outline level, positioned relative to the top of the
// first text line (whose baseline lies 0.905 * size below it), centred
// 0.378 * size above the baseline: a red square for level 1, a grey en dash
// at 73% of the size for level 2, a grey ring for level 3.
#let marker(level, size, dx) = {
  let mid = (0.905 - 0.378) * size
  if level == 0 {
    let a = 0.24 * size
    place(top + left, dx: dx + 0.01 * size, dy: mid - a / 2,
      rect(width: a, height: a, radius: 0.04 * size, fill: red,
        stroke: none))
  } else if level == 1 {
    let d = 0.73 * size
    place(top + left, dx: dx, dy: (0.905 - 0.17) * size - 0.905 * d,
      text(size: d, fill: muted, "–"))
  } else {
    let r = 0.11 * size
    place(top + left, dx: dx + 0.047 * size, dy: mid - r,
      circle(radius: r, fill: none, stroke: 0.06 * size + muted))
  }
}

// Render outline items; every item is content and may be followed in the
// array by an array with its children (the next outline level).
#let outline-items(items, scale: 1, level: 0) = {
  let lv = levels.at(level)
  let size = lv.size * scale
  let i = 0
  while i < items.len() {
    let it = items.at(i)
    let children = none
    if i + 1 < items.len() and type(items.at(i + 1)) == array {
      children = items.at(i + 1)
    }
    block(below: lv.below * scale, above: 0pt, {
      set text(size: size)
      pad(left: lv.text-x * scale, {
        marker(level, size, (lv.marker-x - lv.text-x) * scale)
        it
      })
    })
    if children != none {
      outline-items(children, scale: scale, level: level + 1)
      i += 2
    } else {
      i += 1
    }
  }
}

// A content slide.  `items`: outline (see outline-items), `scale`: autofit
// factor of Impress, `x`: left edge of the outline box, `width`: its width,
// `extra`: content placed on top (figures), drawn below the frame.
#let slide(number, title: none, items: (), scale: 1, x: body-x, width: 740pt,
    extra: none) = {
  if title != none { slide-title(title) }
  if extra != none { extra }
  place(top + left, dx: x, dy: body-top, block(width: width,
    outline-items(items, scale: scale)))
  top-strip
  footer(number)
  pagebreak(weak: true)
}

// The title slide: the title beside a red bar, the author below it in grey.
#let title-slide(title: none, author: none) = {
  top-strip
  place(top + left, dx: body-x, dy: 92pt, barred(title, 44pt, 7pt))
  place(top + left, dx: body-x + 24.5pt, dy: 300pt,
    text(size: 22pt, fill: muted, author))
  footer(none)
  pagebreak(weak: true)
}

// Place a figure (image) scaled into the box x, y, w, h (in pt).
#let fig(path-image, x, y, w, h) = place(top + left, dx: x, dy: y,
  box(width: w, height: h, align(center + horizon, path-image)))

// Dark terminal and editor windows (Zenburn colours) recreating the
// screenshots of the original slides.  The screenshots used a monospaced
// font with 11px wide cells and a line pitch of 23px; `px` is the size of
// one screenshot pixel on the slide, so the text keeps the original layout.
#let zenburn = (
  bg: rgb(44, 44, 44),
  fg: rgb(220, 220, 204),
  green: rgb(96, 180, 138),
  ok: rgb(114, 213, 163),
  blue: rgb(154, 184, 215),
  orange: rgb(223, 175, 143),
  match: rgb(220, 163, 163),
  cyan: rgb(147, 224, 227),
  pink: rgb(236, 147, 211),
  yellow: rgb(240, 223, 175),
  search: rgb(63, 63, 63),
)

// `lines`: array of lines; every line is a string (shown verbatim, styled by
// the regex `rules` given as (regex, function) pairs) or content.
#let screen(x, y, w, h, px, lines, rules: (), left-px: 4, top-px: 0) = {
  let size = 18.27 * px
  let pitch = 23.0 * px
  place(top + left, dx: x, dy: y, block(width: w, height: h,
    fill: zenburn.bg, clip: true, inset: (left: left-px * px, top: top-px * px),
    {
      set text(font: "DejaVu Sans Mono", size: size, fill: zenburn.fg,
        top-edge: 0.928em, bottom-edge: -0.236em, hyphenate: false)
      show raw: set text(font: "DejaVu Sans Mono", size: size)
      show: body => rules.fold(body, (b, r) => {
        show r.at(0): r.at(1)
        b
      })
      for l in lines {
        block(height: pitch, above: 0pt, below: 0pt, width: 10 * w,
          if type(l) == str { raw(l) } else { l })
      }
    }))
}

// Helpers for the editor screenshots (meson_options.txt in vim/kate)
#let ed-col(c, body) = text(fill: c, body)
#let ed-hl(body) = box(fill: zenburn.yellow, outset: (y: 1.5pt),
  text(fill: zenburn.search, body))
