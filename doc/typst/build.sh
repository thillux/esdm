#!/usr/bin/env bash
#
# Build the ESDM documentation from its Typst sources: render the PlantUML
# and draw.io figures to SVG and compile the design document and the slide
# deck to PDF.
#
# Needs typst and plantuml in PATH, and drawio - run under xvfb-run when
# there is no display - for the draw.io figures. With SKIP_DRAWIO=1 the
# committed SVGs of the draw.io figures are used as they are; the nix build
# (nix build .#esdm-doc) does that, as drawio needs a display.
#
# The PDFs are written to OUT_DIR, next to the sources by default. Typst
# warnings fail the build.

set -euxo pipefail

cd "$(dirname "$0")"

OUT_DIR="${OUT_DIR:-.}"
mkdir -p "$OUT_DIR"

for puml in figures/*.puml; do
	plantuml -tsvg "$puml"
done

if [ "${SKIP_DRAWIO:-0}" != 1 ]; then
	drawio="drawio"
	if [ -z "${DISPLAY:-}" ]; then
		drawio="xvfb-run -a drawio"
	fi
	for src in figures/*.drawio; do
		# The light theme gives fixed colours instead of CSS light-dark()
		# ones. The sources use plain (html=0) labels, as Typst does not
		# render the foreignObject of HTML labels.
		$drawio -x -f svg --theme light --embed-svg-fonts false -b 1 \
			-o "${src%.drawio}.svg" "$src"
	done
fi

compile() {
	local log

	log="$(typst compile --root . "$1" "$2" 2>&1)"
	if [ -n "$log" ]; then
		echo "$log" >&2
		exit 1
	fi
}

compile esdm.typ "$OUT_DIR/esdm.pdf"
compile presentations/esdm_presentation_v1.0.0.typ \
	"$OUT_DIR/esdm_presentation_v1.0.0.pdf"
