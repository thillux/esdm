// Slide template of the ESDM presentations.
//
// Recreates the LibreOffice Impress master of the original decks: a 16:9
// page of 793.7pt x 446.5pt, Liberation Sans, red slide titles, black bars
// with two grey lines at the top and the bottom (the slide number sits in the
// bottom bar) and the outline bullets "●" (level 1), "–" (level 2) and
// "●" (level 3).  Impress shrinks the outline text of a slide until it fits;
// the shrink factor of every slide is given as `scale` (1 = 32pt level-1 text).

#let red = rgb(199, 36, 58)
#let link-blue = rgb(29, 153, 243)
#let grey-line = rgb(102, 102, 102)

#let page-width = 793.701pt
#let page-height = 446.457pt

// Left edge of the outline text box and top of its first line.
#let body-x = 39.7pt
#let body-top = 130pt

// Black bar with thin grey lines at the given offsets (in pt from its top).
#let bar(height, lines) = block(width: 100%, height: height, fill: black, {
  for y in lines {
    place(top + left, dy: y - 0.375pt,
      rect(width: 100%, height: 0.75pt, fill: grey-line, stroke: none))
  }
})

// Bars of the content slides: 25.5pt high, grey lines after 6.4pt and 19.1pt.
#let top-bar = place(top + left, dy: 0pt, bar(25.512pt, (6.38pt, 19.13pt)))
#let bottom-bar(number) = place(top + left, dy: 421.8pt, {
  bar(25.512pt, (6.38pt, 19.13pt))
  if number != none {
    place(top + left, dx: 0pt, dy: 16.2pt - 14pt * 0.905,
      box(width: 788.1pt, align(right,
        text(size: 14pt, fill: white, top-edge: 0.905em,
          bottom-edge: -0.212em, str(number)))))
  }
})

// Impress lays out text with the hhea metrics of Liberation Sans (ascender
// 0.905em, descender 0.212em, no line gap); Typst defaults to the smaller
// OS/2 typo metrics, so the edges are set explicitly everywhere.
#let setup(body) = {
  set document(author: "Stephan Müller")
  set page(width: page-width, height: page-height, margin: 0pt)
  set text(font: "Liberation Sans", size: 18pt, lang: "en",
    top-edge: 0.905em, bottom-edge: -0.212em)
  set par(leading: 0pt, spacing: 0pt, justify: false)
  body
}

// Title of a content slide: 44pt, vertically centred on y = 81.8pt.
#let slide-title(title) = place(top + left, dx: body-x, dy: 21.8pt,
  box(height: 120pt, width: page-width - body-x - 10pt,
    align(left + horizon,
      text(size: 44pt, fill: red, title))))

// Outline levels: text size, indent of the bullet and the text, space after
// the paragraph (all for scale 1, as factors of the 32pt level-1 size).
#let levels = (
  (size: 32pt, marker-x: 8.6pt, text-x: 33.9pt, below: 14.2pt),
  (size: 28pt, marker-x: 42.6pt, text-x: 68.2pt, below: 11.5pt),
  (size: 24pt, marker-x: 79.0pt, text-x: 101.8pt, below: 8.3pt),
)

// The bullet of an outline level, positioned relative to the top of the
// first text line (whose baseline lies 0.905 * size below it).  Levels 1 and
// 3 use the OpenSymbol "●" (a disc of a quarter of the text size, centred
// 0.378 * size above the baseline), level 2 an en dash at 73% of the size,
// raised by 0.17 * size.
#let marker(level, size, dx) = {
  if level == 1 {
    let d = 0.73 * size
    place(top + left, dx: dx, dy: (0.905 - 0.17) * size - 0.905 * d,
      text(size: d, "–"))
  } else {
    let r = 0.125 * size
    place(top + left, dx: dx + 0.047 * size,
      dy: (0.905 - 0.378) * size - r,
      circle(radius: r, fill: black, stroke: none))
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
// `extra`: content placed on top (figures), drawn below the bars.
#let slide(number, title: none, items: (), scale: 1, x: body-x, width: 740pt,
    extra: none) = {
  if title != none { slide-title(title) }
  if extra != none { extra }
  place(top + left, dx: x, dy: body-top, block(width: width,
    outline-items(items, scale: scale)))
  top-bar
  bottom-bar(number)
  pagebreak(weak: true)
}

// The title slide: red box with the white title, author centred below it.
#let title-slide(title: none, author: none) = {
  place(top + left, dy: 0pt, bar(25.512pt, (6.38pt, 19.13pt)))
  place(top + left, dx: 0.6pt, dy: 51pt,
    rect(width: 714.3pt, height: 215.5pt, fill: red, stroke: none))
  // three title lines with their baselines at 124.8pt, 174pt and 223.2pt
  place(top + left, dx: 6.3pt, dy: 124.8pt - 44pt * 0.905,
    text(size: 44pt, fill: white, title))
  place(top + left, dx: 0pt, dy: 312.5pt - 32pt * 0.905,
    box(width: 1012pt, align(center, text(size: 32pt, author))))
  place(top + left, dy: 401.926pt, bar(45.751pt,
    (5.5, 21.5, 38.5, 55.5).map(r => r / 61 * 45.751pt)))
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
