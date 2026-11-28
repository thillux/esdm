// Symbols of Font Awesome Free (nixpkgs font-awesome), solid style, by name:
// monochrome glyphs that print in black and white. The HTML has no icon
// font: there an icon shows its fallback text, or nothing.

#import "palette.typ": *

#let icon-font = "Font Awesome 7 Free Solid"
#let icon-codes = (
  folder: "\u{f07b}",
  file: "\u{f15b}",
  check: "\u{f00c}",
  warning: "\u{f071}",
  info: "\u{f05a}",
  terminal: "\u{f120}",
  shield: "\u{f3ed}",
  lock: "\u{f023}",
  key: "\u{f084}",
  server: "\u{f233}",
  microchip: "\u{f2db}",
  flask: "\u{f0c3}",
  bug: "\u{f188}",
  plug: "\u{f1e6}",
)

#let icon(name, fallback: none, fill: none) = context {
  if target() == "html" {
    if fallback != none { fallback }
  } else {
    box(text(font: icon-font, size: 0.85em,
      fill: if fill == none { muted } else { fill }, icon-codes.at(name)))
  }
}

// "yes" of a compliance table: a check mark and its conditions
#let yes(cond) = [#icon("check", fallback: "yes", fill: ink) (#cond)]

// A note that must not be missed, e.g. never to enable test mode in
// production: a warning sign on a light card.
#let warning-note(body) = context {
  if target() == "html" {
    block[*Warning:* #body]
  } else {
    block(width: 100%, fill: surface, stroke: (left: 2pt + ink-soft),
      inset: (x: 10pt, y: 7pt), radius: (right: 3pt),
      grid(columns: (auto, 1fr), column-gutter: 8pt,
        text(font: icon-font, fill: ink, icon-codes.warning), body))
  }
}
