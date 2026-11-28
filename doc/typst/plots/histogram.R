# Histograms of the raw noise source data (figures of chapters 3 and 4),
# rendered with R as their originals were: the relative frequencies of
# data/<name>.csv as bars, a Gaussian kernel density estimate of the bins
# (bandwidth fitted to the curve of the original figure 3.5), the quartiles,
# the mean and the median as vertical lines, and the summary of
# data/meta.csv. The markers differ in dash pattern as well as color, for
# black and white printing; the colors are those of palette.typ.
#
#   Rscript histogram.R <name> <out.svg> <data directory>

args <- commandArgs(trailingOnly = TRUE)
name <- args[1]
out <- args[2]
datadir <- args[3]

meta <- read.csv(file.path(datadir, "meta.csv"), stringsAsFactors = FALSE)
m <- meta[meta$name == name, ]
stopifnot(nrow(m) == 1)
data <- read.csv(file.path(datadir, paste0(name, ".csv")))

ink <- "#0F172A"
muted <- "#475569"
accent <- "#2563EB"
accent_soft <- "#DBEAFE"
line_color <- "#E2E8F0"
source_strong <- "#B45309"

# The bars of hist(): one per value up to the largest one with data
nbars <- m$max + 1
bins <- numeric(nbars)
bins[data$value[data$value < nbars] + 1] <- data$relfreq[data$value < nbars]
ymax <- max(bins)

# Cairo draws the text as outlines: the SVG needs no font to be shown.
svg(out, width = 4.8, height = 3.25, family = "Source Sans 3")
par(mar = c(4.4, 4.2, 3.2, 0.8), mgp = c(3.0, 0.45, 0), tcl = 0.25,
    las = 1, cex = 0.85, fg = ink, col.axis = ink, col.lab = ink,
    col.main = ink)

xlim <- c(-0.04, 1.04) * nbars
ylim <- c(0, 1.08) * ymax
plot(NA, xlim = xlim, ylim = ylim, xaxs = "i", yaxs = "i", axes = FALSE,
     xlab = "", ylab = "Relative Frequency")
title(main = m$title, font.main = 2, cex.main = 1.1, line = 1.85)

# Grid behind the data
ticks <- (seq_len(m$ycount) - 1) * m$ystep
abline(h = ticks, col = line_color, lwd = 0.6)
abline(v = seq(0, 250, 50), col = line_color, lwd = 0.6)

# The bars, filled only: 256 outlines would print as noise
rect(0:(nbars - 1), 0, 1:nbars, bins, col = accent_soft, border = NA)

# density() of the bin values weighted with their relative frequencies
dens <- suppressWarnings(density(0:(nbars - 1), weights = bins / sum(bins),
                                 bw = 1.1, cut = 3))
lines(dens$x, dens$y, col = ink, lwd = 1)

abline(v = c(m$q1, m$q3), col = muted, lty = "dashed", lwd = 1.2)
abline(v = m$mean, col = source_strong, lwd = 1.2)
abline(v = m$median, col = accent, lty = "dotted", lwd = 1.8)

# Complete box, ticks inside on all four sides, labels left and below
box(lwd = 0.8)
axis(1, at = seq(0, 250, 50), lwd = 0, lwd.ticks = 0.8)
axis(3, at = seq(0, 250, 50), labels = FALSE, lwd = 0, lwd.ticks = 0.8)
labelled <- (seq_len(m$ycount) - 1) %% m$ylabelevery == 0
axis(2, at = ticks, labels = ifelse(labelled, sprintf("%.3f", ticks), ""),
     lwd = 0, lwd.ticks = 0.8, cex.axis = 0.9)
axis(4, at = ticks, labels = FALSE, lwd = 0, lwd.ticks = 0.8)

# Above the box with some space to it, below the title
legend("top", inset = c(0, -0.13), xpd = TRUE, horiz = TRUE, bty = "n",
       legend = c("quartiles", "mean", "median", "density"),
       col = c(muted, source_strong, accent, ink),
       lty = c("dashed", "solid", "dotted", "solid"),
       lwd = c(1.2, 1.2, 1.8, 1), seg.len = 1.6, cex = 0.8,
       x.intersp = 0.5, text.width = NA)
mtext(m$sub1, side = 1, line = 1.9, cex = 0.78)
mtext(m$sub2, side = 1, line = 2.8, cex = 0.78)
invisible(dev.off())
