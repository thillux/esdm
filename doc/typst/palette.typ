// The colors of the ESDM documentation: the design document, its HTML, the
// slides, the poster, the plots and - by value - the draw.io and PlantUML
// figures, of which doc/tools/gray_svg.py renders the grayscale variant.
// doc/tools/check_palette.py rejects any color not defined here.
//
// Slate neutrals, one blue accent and one muted warm tone for the entropy
// sources. The comment gives the CIE lightness L*, the gray a color prints
// as: fills placed side by side differ by at least 10 L*, and text on a
// fill keeps a contrast of 4.5:1 - ink on the light fills, white only on
// accent, accent-text, muted and navy.

// The grayscale variant of the design document for black and white
// printing (input color=gray of doc/typst/Makefile): the light colors
// become the grays of the same CIE lightness, as luma() converts, so the
// fills keep the distinctions they make; everything dark - text, numbers,
// bullets, links, rules, plot lines - becomes black for the most contrast.
// Hairlines and card borders darken one step, as very light gray lines
// drop out on a laser printer.
#let grayscale = sys.inputs.at("color", default: "color") == "gray"
#let tone(c, print: none) = if grayscale {
  luma(if print == none { c } else { print })
} else { c }
#let dark(c) = tone(c, print: rgb("#000000"))

#let ink = dark(rgb("#0f172a")) // 8: text, titles, figure labels
#let ink-soft = dark(rgb("#334155")) // 27: figure outlines, inline code
#let muted = dark(rgb("#475569")) // 36: captions, secondary text, arrows
#let faint = tone(rgb("#94a3b8")) // 66: footers, guide lines; time stamps
#let rule = tone(rgb("#cbd5e1"), print: rgb("#94a3b8")) // 85: table rules
#let line-color = tone(rgb("#e2e8f0"), print: rgb("#cbd5e1")) // 92: borders
#let surface = tone(rgb("#f1f5f9")) // 96: containers; external sources
#let surface-code = tone(rgb("#f8fafc")) // 98: code cards
#let background = tone(rgb("#ffffff")) // 100: page background

#let accent = dark(rgb("#2563eb")) // 46: rules, bullets; interfaces
#let accent-text = dark(rgb("#1d4ed8")) // 39: links, chapter numbers
#let accent-soft = tone(rgb("#dbeafe")) // 92: header rows; ESDM processing
#let accent-faint = tone(rgb("#eff6ff")) // 97: abstract card, table headers
#let navy = dark(rgb("#0b1f3a")) // 12: title slide, poster header
#let on-navy = tone(rgb("#60a5fa")) // 67: accent on navy
#let on-navy-soft = tone(rgb("#93c5fd")) // 78: subtitles on navy

#let source = tone(rgb("#e9c08f")) // 80: ESDM-internal entropy sources
#let source-soft = tone(rgb("#f8e1c3")) // 91: eBPF entropy sources
#let source-strong = dark(rgb("#b45309")) // 47: warm lines and text
#let alert = dark(rgb("#b91c1c")) // 40: failure paths, always dashed

// Two tones of code only, for types and keys and for function names; their
// contrast on surface-code is 5.2:1 and 6.8:1.
#let code-type = dark(rgb("#0f766e")) // 44: types, keys of settings
#let code-function = dark(rgb("#6d28d9")) // 37: function and command names

// The highlighting theme of the code blocks, a TextMate theme built from the
// palette: keywords blue, types teal, functions violet, literals warm, the
// labels of PlusCal steps red, comments and console output muted. In the
// grayscale variant all code is black, keywords and labels bold besides,
// comments italic. The most specific scope wins: "keyword.operator" keeps
// symbols in the text color, "keyword.operator.word" makes \in a keyword.
#let raw-rules = (
  ("comment, punctuation.definition.comment", muted, "italic", "italic"),
  ("keyword, storage.modifier, keyword.operator.word, "
    + "keyword.operator.quantifier, meta.preprocessor, "
    + "punctuation.definition.directive, entity.name.section, "
    + "entity.section, markup.heading", accent-text, "", "bold"),
  ("keyword.operator, punctuation", ink-soft, "", ""),
  ("storage.type, support.type, entity.name.type, entity.name.class, "
    + "entity.name.struct, entity.name.enum, entity.name.union, "
    + "support.class, variable.other.key, keyword.name.ini, "
    + "entity.other.attribute-name, support.type.property-name, "
    + "variable.parameter.keyword", code-type, "", ""),
  ("entity.name.function, support.function, variable.function",
    code-function, "", ""),
  ("string, constant, support.constant", source-strong, "", ""),
  ("entity.name.label", alert, "", "bold"),
  ("meta.output, punctuation.definition.prompt", muted, "", ""),
)
#let raw-theme = bytes({
  let entry(scope, c, style) = ("<dict><key>scope</key><string>" + scope
    + "</string><key>settings</key><dict><key>foreground</key><string>"
    + c.to-hex() + "</string><key>fontStyle</key><string>" + style
    + "</string></dict></dict>")
  ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">"
    + "<dict><key>name</key><string>ESDM</string><key>settings</key><array>"
    + "<dict><key>settings</key><dict><key>foreground</key><string>"
    + ink-soft.to-hex() + "</string></dict></dict>"
    + raw-rules.map(((scope, c, style, gray)) => entry(scope, c,
      if grayscale { gray } else { style })).join()
    + "</array></dict></plist>")
})

// The dark terminal and editor windows of the slides (Tailwind tones on
// slate-900): text on a dark background, so lighter tones than above.
#let code = (
  bg: rgb("#0f172a"),
  bar: rgb("#1e293b"),
  border: rgb("#334155"),
  dot: rgb("#475569"),
  title: rgb("#94a3b8"),
  fg: rgb("#e2e8f0"),
  comment: rgb("#94a3b8"),
  keyword: rgb("#93c5fd"),
  string: rgb("#86efac"),
  prompt: rgb("#60a5fa"),
  ok: rgb("#4ade80"),
  skip: rgb("#fbbf24"),
  warn: rgb("#fdba74"),
  debug: rgb("#93c5fd"),
  verbose: rgb("#a7f3d0"),
  match: rgb("#f472b6"),
  search-bg: rgb("#fbbf24"),
  search-fg: rgb("#0f172a"),
)
