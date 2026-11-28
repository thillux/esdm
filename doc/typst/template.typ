// Document template of the ESDM design document.
//
// The numbering follows the LaTeX article class the document was originally
// typeset with - numbered sections, figures and equations numbered per
// section -, the look is a calmer, more open one: one type family throughout -
// the text in Source Serif 4 at 10pt with generous leading and spacing between
// paragraphs instead of indents, headings, captions, the title page and the
// running header in Source Sans 3 - the face of the slides -, code in Source
// Code Pro, formulas in STIX Two Math, whose letters match the serif; side
// margins of 28 mm for lines of some 90 characters; dark slate with one blue
// accent; chapters open a page under a large chapter number; tables with
// horizontal rules only and a light blue header row; code in soft grey cards.

#import "inputs.typ": esdm-version, doc-date
// The paper size, a4 or us-letter, an input of doc/typst/Makefile.
#let paper = sys.inputs.at("paper", default: "a4")
#assert(paper in ("a4", "us-letter"),
  message: "paper must be a4 or us-letter, not " + paper)

#let body-font = "Source Serif 4"
#let sans-font = "Source Sans 3"
#let mono-font = "Source Code Pro"
#let math-font = "STIX Two Math"

#import "palette.typ": *
#import "icons.typ": icon, yes, warning-note
#import "acronyms.typ": ac, acs, in-lists, init-acronyms, acronym-index
// The roles of the palette here: accent-text for blue text, accent for
// blue rules, bullets and the band of the title page.
#let accent-light = accent-faint
#let hairline = rule
#let code-fill = surface-code
#let code-stroke = line-color

// What the running header names on the left of every page
#let doc-title = state("esdm-doc-title", none)

// Paragraph with a run-in heading (LaTeX \paragraph).
#let paragraph(title, body) = block(above: 1.4em, below: 0.6em,
  par(first-line-indent: 0pt)[#text(font: sans-font, weight: "semibold",
    fill: ink, title)#h(0.8em)#body])

// Number of the current section, used for per-section numbering.
#let section-number(loc) = {
  let h = counter(heading).at(loc)
  if h.len() == 0 { 0 } else { h.first() }
}

// Format a per-section number "S.N" for a counter value at a location.
#let per-section(kind-counter, loc, fmt: "1.1") = {
  let s = counter(heading).at(loc)
  let n = kind-counter.at(loc).first()
  numbering(fmt, if s.len() == 0 { 0 } else { s.first() }, n)
}

// Reference to an equation without parentheses ("equation 2.3").
#let eqref(label) = context {
  let el = query(label).first()
  link(el.location(), per-section(counter(math.equation), el.location()))
}

// The number of a heading as it is displayed.
#let heading-number(h) = numbering(h.numbering,
  ..counter(heading).at(h.location()))

// A part of the document: a page of its own under "Part I", "Part II", and an
// entry of the contents. The chapters number on through the parts; a hidden
// figure of kind "part" carries the entry, as an outline lists only headings
// and figures.
#let part(title) = page(header: none, footer: none, {
  place(hide(figure(kind: "part", supplement: [Part], numbering: "I",
    caption: title, outlined: true, [])))
  v(1fr)
  text(font: sans-font, size: 11pt, weight: "semibold", fill: accent-text,
    tracking: 0.14em, upper[Part #context counter(figure.where(kind:
      "part")).display("I")])
  v(8pt)
  text(font: sans-font, size: 30pt, weight: "bold", fill: ink, title)
  v(10pt, weak: true)
  line(length: 44pt, stroke: 3pt + accent)
  v(2fr)
})

// A title of the front matter (contents, lists): set like a chapter title,
// but no heading - it neither numbers nor appears in the outline.
#let front-title(body) = block(below: 1.4em, {
  text(font: sans-font, size: 22pt, weight: "semibold", fill: ink, body)
  v(6pt, weak: true)
  line(length: 36pt, stroke: 2.5pt + accent)
})

// The running header: the title of the document on the left, the chapter
// on the right, over a hairline; none on the title page and on the first
// page of a chapter.
#let running-header = context {
  let page = here().page()
  if page == 1 { return }
  if query(heading.where(level: 1)).any(h => h.location().page() == page) {
    return
  }
  let chapters = query(heading.where(level: 1).before(here()))
    .filter(h => h.outlined)
  set text(font: sans-font, size: 8.5pt, fill: muted)
  grid(columns: (1fr, auto), column-gutter: 1em,
    doc-title.get(),
    if chapters.len() > 0 {
      let chapter = chapters.last()
      if chapter.numbering != none [#heading-number(chapter)#h(0.6em)]
      chapter.body
    })
  v(-5pt)
  line(length: 100%, stroke: 0.4pt + hairline)
}

#let running-footer = context {
  if here().page() == 1 { return }
  set text(font: sans-font, size: 9pt, fill: muted)
  align(center, counter(page).display("1"))
}

// The numbering of figures, tables and equations and the references to
// them.
#let numbering-rules(body) = {
  set heading(numbering: "1.1.1")
  set figure(numbering: n => context {
    let s = counter(heading).get()
    numbering("1.1", if s.len() == 0 { 0 } else { s.first() }, n)
  })
  show figure.where(kind: table): set figure(numbering: "1")
  show figure.where(kind: table): set figure.caption(position: top)
  // Long tables continue on the next page instead of leaving a gap; cells
  // are set ragged, as justified narrow columns hyphenate.
  show figure.where(kind: table): set block(breakable: true)
  show table: set par(justify: false)
  set math.equation(numbering: n => context {
    let s = counter(heading).get()
    text(fill: muted, numbering("(1.1)", if s.len() == 0 { 0 } else {
      s.first() }, n))
  })
  // References show the bare number: the text says "figure 2.1",
  // "section 2.2" or "chapter 3" itself.
  set ref(supplement: none)
  show ref: it => {
    let el = it.element
    if el != none and el.func() == math.equation {
      link(el.location(), per-section(counter(math.equation), el.location()))
    } else if el != none and el.func() == figure and el.kind == image {
      link(el.location(),
        per-section(counter(figure.where(kind: image)), el.location()))
    } else { it }
  }
  body
}

// The authors as (name, e-mail) pairs: the title page marks each name with
// a dagger or a like symbol and gives the address in a footnote.
#let author-names(authors) = authors.map(a => a.at(0))

#let paged-doc(title, authors, date, abstract, body) = {
  set document(title: title, author: author-names(authors))
  doc-title.update(title)
  init-acronyms()
  set page(
    paper: paper,
    margin: (x: 28mm, top: 30mm, bottom: 27mm),
    header-ascent: 40%,
    footer-descent: 40%,
    header: running-header,
    footer: running-footer,
  )
  set text(font: body-font, size: 10pt, lang: "en", fill: ink,
    number-type: "lining")
  set par(justify: true, leading: 0.74em, spacing: 1.15em,
    first-line-indent: 0pt)
  // Typst sets raw text at 0.8em: Source Code Pro at 0.92 of the text
  // matches the x-height of Source Serif 4.
  show raw: set text(font: mono-font, size: 1.15em)
  // Highlighting in the colors of the palette, in gray for the grayscale
  // variant, with syntaxes for the languages Typst ships none for.
  set raw(theme: raw-theme, syntaxes: ("syntaxes/tla.sublime-syntax",
    "syntaxes/console.sublime-syntax", "syntaxes/meson.sublime-syntax",
    "syntaxes/strongswan.sublime-syntax"))
  // The grayscale variant shows the gray renderings of the figures and the
  // plots, <dir>/<name>.gray.svg of doc/tools/gray_svg.py.
  show image: it => {
    let src = it.source
    if (not grayscale or type(src) != str or not src.ends-with(".svg")
        or src.ends-with(".gray.svg")) { return it }
    let parts = src.split("/")
    image("/" + parts.at(-2) + "/" + parts.last().slice(0, -4) + ".gray.svg",
      width: it.at("width", default: auto),
      height: it.at("height", default: auto),
      alt: it.at("alt", default: none))
  }
  show raw.where(block: true): set par(justify: false, leading: 0.55em)
  show raw.where(block: true): it => block(width: 100%, fill: code-fill,
    stroke: 0.5pt + code-stroke, radius: 3pt, inset: (x: 9pt, y: 7pt), it)
  // Long identifiers may break after an underscore or a slash rather than
  // stretching the line, but not at their end, which would push the
  // punctuation after them, e.g. a ")", to the next line alone.
  show raw.where(block: false): it => text(font: mono-font,
    fill: ink-soft,
    it.text.replace("_", "_\u{200B}").replace("/", "/\u{200B}")
      .trim("\u{200B}", at: end))
  show math.equation: set text(font: math-font)
  show math.equation.where(block: true): set block(above: 1.1em,
    below: 1.1em)

  set list(indent: 0.3em, body-indent: 0.6em, spacing: 0.8em,
    // The third marker is drawn: Source Serif 4 has no white bullet.
    marker: (text(fill: accent)[•], text(fill: muted)[–],
      box(height: 0.6em, align(horizon,
        circle(radius: 1.4pt, stroke: 0.6pt + muted)))))
  set enum(indent: 0.2em, body-indent: 0.6em, spacing: 0.8em, full: true,
    numbering: (..ns) => {
      let ns = ns.pos()
      text(fill: accent-text, numbering(("1.", "(a)", "i.").at(
        calc.min(ns.len(), 3) - 1), ns.last()))
    })
  set terms(separator: h(0.6em), hanging-indent: 1.5em, spacing: 0.7em)
  show terms.item: it => block[#text(font: sans-font, weight: "semibold",
    fill: ink, it.term)#h(0.6em)#it.description]
  show list: set block(above: 0.95em, below: 0.95em)
  show enum: set block(above: 0.95em, below: 0.95em)
  show strong: set text(fill: ink)

  show link: it => if type(it.dest) == str {
    text(fill: accent-text, it)
  } else { it }

  show: numbering-rules

  // Headings in Source Sans 3: a chapter opens a page, under its number in
  // semibold blue - "Appendix A" in the appendix -, the others carry their
  // number in blue in front of a hanging title.
  show heading: set text(font: sans-font, fill: ink)
  show heading: it => {
    let size = (14pt, 11.5pt, 10.5pt).at(calc.min(it.level, 4) - 2,
      default: 10.5pt)
    set text(size: size, weight: "semibold")
    set par(first-line-indent: 0pt, justify: false, leading: 0.5em)
    block(above: if it.level == 2 { 2em } else { 1.7em },
      below: if it.level == 2 { 1em } else { 0.85em },
      sticky: true,
      if it.numbering != none {
        grid(columns: (auto, 1fr), column-gutter: 0.75em,
          text(fill: accent-text, counter(heading).display(it.numbering)),
          it.body)
      } else { it.body })
  }
  // Figures and equations are numbered per chapter.
  show heading.where(level: 1): it => {
    counter(figure.where(kind: image)).update(0)
    counter(math.equation).update(0)
    pagebreak(weak: true)
    set par(first-line-indent: 0pt, justify: false, leading: 0.4em)
    block(above: 0pt, below: 2.4em, sticky: true, {
      v(26pt)
      if it.numbering != none {
        let num = counter(heading).display(it.numbering)
        if type(it.numbering) == str and it.numbering.starts-with("A") {
          text(size: 10pt, weight: "semibold", fill: accent-text,
            tracking: 0.12em, upper[Appendix])
          v(2pt)
        }
        text(size: 36pt, weight: "semibold", fill: accent-text, num)
        v(10pt, weak: true)
      }
      text(size: 24pt, weight: "semibold", it.body)
      v(12pt, weak: true)
      line(length: 36pt, stroke: 2.5pt + accent)
    })
  }
  set figure(gap: 1em)
  show figure: set block(above: 1.8em, below: 1.8em)
  show figure.caption: it => {
    set text(size: 9.5pt)
    set par(justify: false, leading: 0.55em)
    let label = text(font: sans-font, weight: "semibold", fill: accent-text,
      [#it.supplement #context it.counter.display(it.numbering)])
    block(width: 100%, sticky: true, align(center, [#label#h(0.5em)#it.body]))
  }
  // Tables: horizontal rules only, a light blue header row in Source Sans
  // 3 semibold.
  set table(
    stroke: (x, y) => (top: if y == 0 { 0.8pt + ink } else {
      0.4pt + hairline }, bottom: 0.8pt + ink, left: none, right: none),
    fill: (x, y) => if y == 0 { accent-light },
    inset: (x: 6pt, y: 4.5pt),
  )
  show table.cell.where(y: 0): set text(font: sans-font, weight: "semibold",
    fill: ink)
  set footnote.entry(separator: line(length: 30%, stroke: 0.5pt + hairline),
    gap: 0.5em)
  show footnote.entry: set text(size: 8.5pt)
  show footnote.entry: set par(first-line-indent: 0pt, leading: 0.5em)

  // The title page: a blue band on top, the title in Source Sans 3 with a
  // short blue line under it, author and version, the abstract on a light
  // blue card at the foot of the page.
  page(margin: (x: 28mm, top: 0pt, bottom: 25mm), header: none,
    footer: none, {
    set par(first-line-indent: 0pt, justify: false)
    // In the grayscale variant a light band rather than a black one
    place(top + left, dx: -28mm, rect(width: 100% + 56mm, height: 9mm,
      fill: if grayscale { faint } else { accent }))
    v(62mm)
    text(font: sans-font, size: 10pt, weight: "semibold", fill: accent-text,
      tracking: 0.14em, upper[ESDM Design Document and Manual])
    v(6mm)
    block(text(font: sans-font, size: 32pt, weight: "bold", fill: ink,
      title))
    v(5mm)
    line(length: 44pt, stroke: 3pt + accent)
    v(9mm)
    {
      // Symbols instead of numbers, only here: the footnotes of the text
      // start at 1 again after the title page.
      set footnote(numbering: n => ("†", "‡", "§", "¶").at(n - 1))
      text(font: sans-font, size: 13pt, fill: ink,
        authors.map(a => [#a.at(0)#footnote(raw(a.at(1)))]).join(", "))
    }
    v(3mm)
    text(font: sans-font, size: 11.5pt, fill: muted, date)
    v(1fr)
    if abstract != none {
      block(width: 100%, fill: accent-light, radius: 4pt, inset: 14pt, {
        text(font: sans-font, size: 9pt, weight: "semibold", fill: accent-text,
          tracking: 0.12em, upper[Abstract])
        v(4pt)
        set text(size: 9.5pt)
        set par(justify: true, leading: 0.6em)
        abstract
      })
    }
  })

  counter(footnote).update(0)

  // Table of contents, lists of figures and tables.
  {
    set par(first-line-indent: 0pt, justify: false)
    front-title[Contents]
    show outline.entry.where(level: 1): it => {
      v(1.1em, weak: true)
      link(it.element.location(), text(font: sans-font, weight: "semibold",
        fill: ink, it.indented(text(fill: accent-text, it.prefix()),
        [#it.body()#h(1fr)#it.page()])))
    }
    // A part: its number and title above its chapters, no page number
    show outline.entry: it => {
      if it.element.func() != figure or it.element.kind != "part" {
        return it
      }
      v(1.8em, weak: true)
      link(it.element.location(), text(font: sans-font, size: 10pt,
        weight: "semibold", fill: accent-text, tracking: 0.12em,
        upper[Part #numbering("I", ..it.element.counter.at(
          it.element.location()))#h(0.8em)#it.element.caption.body]))
      v(0.4em, weak: true)
    }
    set outline.entry(fill: box(width: 1fr, repeat(gap: 0.5em,
      text(fill: hairline)[.])))
    outline(title: none, indent: auto, depth: 3,
      target: selector(heading).or(figure.where(kind: "part")))
    pagebreak(weak: true)
    // Entries of the lists of figures and tables: number, caption, dots.
    show outline.entry: it => {
      if it.element.func() != figure { return it }
      let loc = it.element.location()
      let num = if it.element.kind == image {
        per-section(counter(figure.where(kind: image)), loc)
      } else {
        str(counter(figure.where(kind: table)).at(loc).first())
      }
      block(above: 0.6em, below: 0.6em, link(loc, grid(
        columns: (2.6em, 1fr),
        text(font: sans-font, fill: accent-text, num),
        par(justify: false)[#it.element.caption.body#box(width: 1fr,
          repeat(gap: 0.5em, text(fill: hairline)[.]))#it.page()])))
    }
    in-lists.update(true)
    front-title[List of Figures]
    outline(title: none, target: figure.where(kind: image))
    v(2em)
    front-title[List of Tables]
    outline(title: none, target: figure.where(kind: table))
    in-lists.update(false)
  }

  body
}

// The design document.
#let esdm-doc(
  title: none,
  authors: (),
  date: none,
  abstract: none,
  body,
) = paged-doc(title, authors, date, abstract, body)

// Switch to appendix numbering (A, B, ...).
#let appendix(body) = {
  counter(heading).update(0)
  set heading(numbering: "A.1")
  body
}
