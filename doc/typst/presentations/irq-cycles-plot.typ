// Slide 14: "Mean Duration in Cycles for one IRQ" - an R line plot (type
// "b") redrawn from the data in data/irq-cycles.csv.  The geometry follows
// the original slide: all coordinates are slide coordinates in pt, the plot
// is placed onto the slide with `place` at its absolute position.

#let rows = {
  let lines = read("data/irq-cycles.csv").split("\n").filter(
    l => l.trim() != "" and not l.starts-with("#"))
  csv(bytes(lines.join("\n")), row-type: dictionary)
}

// axis mapping of the original plot
#let px(v) = 477.213pt + (758.438pt - 477.213pt) * (v / 1000)
#let py(v) = 207.610pt - (207.610pt - 74.609pt) * ((v - 40) / 60)

#let sw = rgb(255, 0, 0)
#let avx = rgb(0, 0, 255)
#let legacy = rgb(190, 190, 190)
#let thin = 0.458pt

// a label centred (or left-aligned and vertically centred) on (x, y)
#let lbl(x, y, body, size: 6.1pt, anchor: center + horizon, weight: "regular",
    angle: 0deg) = context {
  let c = rotate(angle, reflow: true, text(font: "Liberation Sans",
    size: size, weight: weight, top-edge: "cap-height",
    bottom-edge: "baseline", body))
  let m = measure(c)
  let dx = if anchor.x == left { 0pt } else { m.width / 2 }
  place(top + left, dx: x - dx, dy: y - m.height / 2, c)
}

// R type "b": points joined by lines that stop short of the points
#let series(key, colour) = {
  let pts = rows.map(r => (px(float(r.collection_size)), py(float(r.at(key)))))
  let gap = 2.4pt
  for i in range(pts.len() - 1) {
    let (x0, y0) = pts.at(i)
    let (x1, y1) = pts.at(i + 1)
    let dx = (x1 - x0) / 1pt
    let dy = (y1 - y0) / 1pt
    let len = calc.sqrt(dx * dx + dy * dy)
    if len * 1pt > 2 * gap {
      let ux = dx / len
      let uy = dy / len
      place(top + left, line(
        start: (x0 + ux * gap, y0 + uy * gap),
        end: (x1 - ux * gap, y1 - uy * gap),
        stroke: thin + colour))
    }
  }
  for (x, y) in pts {
    place(top + left, dx: x - 1.37pt, dy: y - 1.37pt,
      circle(radius: 1.37pt, fill: colour, stroke: thin + colour))
  }
}

#let irq-cycles-plot = {
  // frame, axes and ticks
  place(top + left, dx: 470.353pt, dy: 56.2pt,
    rect(width: 776.5pt - 470.353pt, height: 208.5pt - 56.2pt,
      stroke: thin + black))
  place(top + left, line(start: (477.213pt, 208.546pt),
    end: (758.438pt, 208.546pt), stroke: thin))
  for v in (0, 200, 400, 600, 800, 1000) {
    place(top + left, line(start: (px(v), 208.546pt), end: (px(v), 212.2pt),
      stroke: thin))
    lbl(px(v), 215.4pt, str(v))
  }
  place(top + left, line(start: (470.353pt, py(40)), end: (470.353pt, py(100)),
    stroke: thin))
  for v in (40, 50, 60, 70, 80, 90, 100) {
    place(top + left, line(start: (466.696pt, py(v)), end: (470.353pt, py(v)),
      stroke: thin))
    lbl(460.6pt, py(v), str(v), angle: -90deg)
  }
  // titles
  lbl(623.4pt, 41.6pt, [Mean Duration in Cycles for one IRQ], size: 7.3pt,
    weight: "bold")
  lbl(617.8pt, 233.0pt, [LRNG collection size])
  lbl(446.3pt, 132.1pt, [Mean Duration in Cycles for one IRQ], angle: -90deg)
  // data
  place(top + left, line(start: (481.72pt, 81.27pt), end: (765.184pt, 81.27pt),
    stroke: thin + legacy))
  series("software_sha256", sw)
  series("avx2_sha512", avx)
  // legend
  place(top + left, dx: 660.0pt, dy: 96.8pt,
    rect(width: 80.9pt, height: 29.3pt, stroke: thin + black, fill: white))
  for (i, (name, colour)) in (
    ([Software SHA-256], sw), ([AVX2 SHA-512], avx),
    ([Legacy /dev/random], legacy)).enumerate() {
    let y = 104.118pt + i * 7.313pt
    place(top + left, line(start: (665.49pt, y), end: (676.488pt, y),
      stroke: thin + colour))
    lbl(680.8pt, y, name, anchor: left + horizon)
  }
}
