// Histograms of the raw noise source data (figures 3.1 to 3.6, and the
// eBPF entropy sources of chapter 4), rendered with R: plots/histogram.R
// draws plots/<name>.svg from data/<name>.csv and the summary in
// data/meta.csv (doc/typst/Makefile).
//
// Usage: #import "../plots/histogram.typ": histogram
//        #figure(histogram("riscv"), caption: [...])

#let histogram(name, width: 345.6pt) = image("/plots/" + name + ".svg",
  width: width)
