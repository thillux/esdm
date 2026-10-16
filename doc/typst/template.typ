// Document template of the ESDM design document.
//
// The layout follows the LaTeX article class (12pt, A4) the document was
// originally typeset with (10pt): New Computer Modern, numbered sections, figures
// and equations numbered per section, run-in paragraph headings.

#let body-font = "New Computer Modern"
#let mono-font = "DejaVu Sans Mono"

// Paragraph with a run-in heading (LaTeX \paragraph).
#let paragraph(title, body) = block(above: 1.4em, below: 0.51em,
  par(first-line-indent: 0pt)[#text(weight: "bold", title)#h(1em)#body])

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

#let esdm-doc(
  title: none,
  author: none,
  date: none,
  abstract: none,
  body,
) = {
  set document(title: title, author: "Stephan Müller")
  set page(
    paper: "a4",
    margin: (left: 124.8pt, right: 125.5pt, top: 128.6pt, bottom: 126pt),
    footer-descent: 46pt,
    footer: context align(center, counter(page).display("1")),
  )
  set text(font: body-font, size: 10pt, lang: "en")
  set par(justify: true, leading: 0.51em, spacing: 0.51em,
    first-line-indent: 1.5em)
  show raw: set text(font: mono-font, size: 0.9em)
  show raw.where(block: true): set par(justify: false)
  // Long identifiers may break after an underscore or a slash rather than
  // stretching the line.
  show raw.where(block: false): it => text(font: mono-font,
    it.text.replace("_", "_\u{200B}").replace("/", "/\u{200B}"))
  show math.equation: set text(font: "New Computer Modern Math")
  show math.equation.where(block: true): set block(above: 1em, below: 1em)

  // Lists in the style of the LaTeX defaults used by the original.
  set list(indent: 1em, body-indent: 0.6em, spacing: 0.95em,
    marker: ([•], [–], [$succ$]))
  set enum(indent: 0.9em, body-indent: 0.6em, spacing: 0.95em, full: true,
    numbering: (..ns) => {
      let ns = ns.pos()
      numbering(("1.", "(a)", "i.").at(calc.min(ns.len(), 3) - 1), ns.last())
    })
  set terms(separator: h(0.6em), hanging-indent: 1.5em, spacing: 0.5em)
  show list: set block(above: 1em, below: 1em)
  show enum: set block(above: 1em, below: 1em)

  // URLs are blue as in the hyperref setup of the original.
  show link: it => if type(it.dest) == str {
    text(fill: rgb(0, 0, 255), it)
  } else { it }

  // Headings.
  set heading(numbering: "1.1.1")
  show heading: set text(weight: "bold")
  show heading: it => {
    let size = if it.level == 1 { 14.4pt } else if it.level == 2 {
      12pt
    } else { 10pt }
    let gap = if it.level == 1 { 1em } else { 1em }
    set text(size: size)
    set par(first-line-indent: 0pt, justify: false)
    block(above: if it.level == 1 { 1.6em } else { 1.5em },
      below: if it.level == 1 { 1em } else { 1em },
      sticky: true,
      if it.numbering != none {
        grid(columns: (auto, 1fr), column-gutter: gap,
          counter(heading).display(it.numbering), it.body)
      } else { it.body })
  }
  // Figures and equations are numbered per section.
  show heading.where(level: 1): it => {
    counter(figure.where(kind: image)).update(0)
    counter(math.equation).update(0)
    it
  }
  set figure(numbering: n => context {
    let s = counter(heading).get()
    numbering("1.1", if s.len() == 0 { 0 } else { s.first() }, n)
  })
  show figure.where(kind: table): set figure(numbering: "1")
  set figure(gap: 1.2em)
  show figure: set block(above: 1.6em, below: 1.6em)
  show figure.caption: set par(justify: false)
  set math.equation(numbering: n => context {
    let s = counter(heading).get()
    numbering("(1.1)", if s.len() == 0 { 0 } else { s.first() }, n)
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

  set table(stroke: 0.5pt, inset: (x: 5pt, y: 3pt))
  set footnote.entry(separator: line(length: 35%, stroke: 0.5pt))
  show footnote.entry: set text(size: 8pt)
  show footnote.entry: set par(first-line-indent: 0pt, leading: 0.5em)

  // Title (LaTeX \maketitle of the article class).
  {
    set par(first-line-indent: 0pt)
    v(40pt)
    align(center, {
      text(size: 17.28pt, title)
      v(1.5em)
      text(size: 12pt, author)
      v(0.8em)
      text(size: 12pt, date)
    })
    v(2em)
    if abstract != none {
      align(center, text(size: 9pt, weight: "bold")[Abstract])
      v(0.2em)
      pad(x: 30pt, {
        set text(size: 9pt)
        set par(first-line-indent: (amount: 1.5em, all: true),
          leading: 0.55em)
        abstract
      })
    }
  }

  // Table of contents, lists of figures and tables.
  {
    set par(first-line-indent: 0pt, justify: false)
    show outline.entry.where(level: 1): it => {
      v(1.1em, weak: true)
      link(it.element.location(), strong(it.indented(it.prefix(),
        [#it.body()#h(1fr)#it.page()])))
    }
    set outline.entry(fill: box(width: 1fr, repeat(gap: 0.6em)[.]))
    outline(title: [Contents], indent: auto, depth: 3)
    show outline.entry.where(level: 1): it => {
      v(0.4em, weak: true)
      link(it.element.location(), it.indented(it.prefix(),
        [#it.body()#box(width: 1fr, repeat(gap: 0.6em)[.])#it.page()]))
    }
    // Entries of the lists of figures and tables: number, caption, dots.
    show outline.entry: it => {
      if it.element.func() != figure { return it }
      let loc = it.element.location()
      let num = if it.element.kind == image {
        per-section(counter(figure.where(kind: image)), loc)
      } else {
        str(counter(figure.where(kind: table)).at(loc).first())
      }
      block(above: 0.55em, below: 0.55em, link(loc, pad(left: 1.5em,
        grid(columns: (2.3em, 1fr), num,
          par(justify: false)[#it.element.caption.body#box(width: 1fr,
            repeat(gap: 0.6em)[.])#it.page()]))))
    }
    v(1em)
    outline(title: [List of Figures], target: figure.where(kind: image))
    v(1em)
    outline(title: [List of Tables], target: figure.where(kind: table))
  }

  body
}

// Switch to appendix numbering (A, B, ...).
#let appendix(body) = {
  counter(heading).update(0)
  set heading(numbering: "A.1")
  body
}
