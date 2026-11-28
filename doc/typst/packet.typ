// Packet diagrams in the style of the RFCs, for the messages of the EGD
// protocol: a ruler of the bit numbers on top - bit 0 is the most
// significant bit of the first byte -, below it one box per field in rows
// of 32 bits, each box as wide as its field.
//
//   #exchange([`0x01` read],
//     [Request], (command("0x01"), field(8)[Length]),
//     [Reply], (field(8)[Count], field(auto)[Count bytes]),
//   )
//
// The ruler and the messages are grids of their own with the same columns,
// a label column and one column per bit, so that their bits line up.

#import "palette.typ": *
#import "template.typ": sans-font

#let row-height = 16pt
#let label-width = 4.2em
#let box-stroke = 0.6pt + ink-soft
#let open-stroke = (paint: ink-soft, thickness: 0.6pt, dash: (2pt, 1.5pt))
#let tick-stroke = 0.4pt + muted

// A field of `bits` bits. With `bits: auto` the field has a variable length,
// which its label names: it fills the rest of its row, its right edge dashed.
// A field crossing the end of a row continues on the next one, labelled
// with `short`, by default its label.
#let field(bits, label, short: none, fill: none) = {
  assert(bits == auto or (type(bits) == int and bits > 0),
    message: "the bits of a field are a positive number or auto")
  (bits: bits, label: label, short: if short == none { label } else { short },
    fill: fill)
}

// The command byte that starts every request.
#let command(code) = field(8, raw(code), fill: accent-soft)

// The cells of the fields in rows of `bits` columns and the number of rows.
#let field-cells(fields, bits) = {
  let cells = ()
  let pos = 0
  let rows = 0
  for f in fields {
    let rest = if f.bits == auto { bits - pos } else { f.bits }
    let first = true
    while rest > 0 {
      if pos == 0 { rows += 1 }
      let n = calc.min(rest, bits - pos)
      let last = n == rest
      cells.push(grid.cell(colspan: n, fill: f.fill, inset: (x: 3pt),
        stroke: (top: box-stroke, bottom: box-stroke, left: box-stroke,
          right: if f.bits == auto and last { open-stroke } else {
            box-stroke }),
        align(center + horizon, if first { f.label } else {
          text(fill: muted)[#f.short (cont.)]
        })))
      pos = calc.rem(pos + n, bits)
      rest -= n
      first = false
    }
  }
  (cells, rows)
}

#let bit-columns(bits) = (label-width, ..((1fr,) * bits))

// The ruler: the number of every bit, a long tick at each byte and a short
// one at each bit.
#let ruler(bits) = grid(
  columns: bit-columns(bits),
  rows: (auto, 2pt, 2.5pt),
  [], ..range(bits).map(i => align(center + bottom,
    text(size: 6pt, fill: muted, str(i)))),
  [], ..range(bits).map(i => grid.cell(stroke: (
    left: if calc.rem(i, 8) == 0 { tick-stroke },
    right: if i == bits - 1 { tick-stroke }), [])),
  [], ..range(bits).map(i => grid.cell(stroke: (left: tick-stroke,
    right: if i == bits - 1 { tick-stroke }), [])),
)

// One message under its name; `none` for a message that is not sent.
#let message(name, fields, bits) = {
  let label = box(width: 100%, height: row-height, inset: (right: 0.7em),
    align(right + horizon, text(fill: muted, name)))
  if fields == none {
    return grid(columns: (label-width, 1fr), rows: row-height, label,
      align(left + horizon, pad(left: 3pt, text(fill: muted)[none])))
  }
  let (cells, rows) = field-cells(fields, bits)
  grid(columns: bit-columns(bits), rows: row-height,
    grid.cell(rowspan: rows, align(top, label)), ..cells)
}

// The messages of one command under its title: the ruler, then the names
// and fields of the messages in turn.
#let exchange(title, ..messages, bits: 32) = {
  let m = messages.pos()
  assert(calc.rem(m.len(), 2) == 0,
    message: "exchange takes the messages as pairs of name and fields")
  set text(font: sans-font, size: 8pt, fill: ink)
  let parts = (pad(left: label-width, text(size: 8.5pt, weight: "semibold",
    title)), 4pt, ruler(bits))
  for i in range(0, m.len(), step: 2) {
    if i > 0 { parts.push(5pt) }
    parts.push(message(m.at(i), m.at(i + 1), bits))
  }
  block(width: 100%, breakable: false, stack(..parts))
}

// The exchanges of one figure, one below the other.
#let exchanges(..blocks) = stack(spacing: 13pt, ..blocks.pos())
