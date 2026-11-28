# Build the ESDM documentation from its Typst sources.
#
#   make                  the design document as PDF/A-2b in A4 and US Letter
#                         (esdm-a4.pdf, esdm-letter.pdf), in grayscale for
#                         black and white printing (esdm-a4-gray.pdf,
#                         esdm-letter-gray.pdf), the slide deck and the
#                         poster as PDF/A-2b
#   make poster           only the A0 poster, esdm_poster.pdf
#   make figures          only render the draw.io and PlantUML figures to SVG
#   make check-palette    reject colors that are not in palette.typ
#   make check-identifiers  reject meson options and functions that do not exist
#   make check-options    the option reference is current with meson_options.txt
#   make diff REV=<rev>   both documents with the changes since git revision
#                         <rev> marked: esdm-diff.pdf, esdm_presentation-diff.pdf
#   make clean
#
# Needs typst, plantuml, graphviz, R, qrencode, python3 and drawio (run under
# xvfb-run when there is no display; drawio-headless of nixpkgs does that on
# its own), and for the diff git. With all of these and the fonts from
# nixpkgs:
#
#   nix build .#esdm-doc                  the PDFs
#   nix run .#esdm-doc-diff -- <rev>      make diff REV=<rev>
#   nix develop .#doc                     a shell to run make in
#
# A Typst warning fails the build. The documents are written to OUT (this
# directory by default), the trees make diff compares to BUILD. The SVGs of
# the figures are rendered next to their sources and are not tracked by
# git.
#
# The documents carry VERSION, the version of meson.build, and the date of
# SOURCE_DATE_EPOCH, by default the time of the last commit: the same tree
# gives the same files. nix build passes both, as it has neither.

TYPST ?= typst
PLANTUML ?= plantuml
DOT ?= dot
RSCRIPT ?= Rscript
QRENCODE ?= qrencode
PYTHON ?= python3
GIT ?= git
ifeq ($(DISPLAY)$(WAYLAND_DISPLAY),)
DRAWIO ?= xvfb-run -a drawio
else
DRAWIO ?= drawio
endif

# The light theme gives fixed colours instead of CSS light-dark() ones. The
# sources use plain (html=0) labels, as Typst does not render the
# foreignObject of HTML labels.
#
# --no-sandbox: Chromium's sandbox needs an unprivileged user namespace or
# else a setuid root chrome-sandbox. Ubuntu since 24.04 (AppArmor) and the
# GitHub runners allow neither to the nix build, and the one in the nix
# store cannot be setuid: drawio aborts at once (SIGTRAP, make Error 133).
# It only renders our own figures here.
DRAWIO_FLAGS ?= --no-sandbox -x -f svg --theme light --embed-svg-fonts false -b 1

OUT ?= .
BUILD ?= build

# Every drawio and plantuml run is a process of its own that takes seconds
# to start: render the figures side by side, on all CPUs unless make was
# given -j. drawio-headless gives each run an X display and a configuration
# directory of its own, so they do not get in each other's way.
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 4)
endif
MAKEFLAGS += --output-sync=target

# DRAWIO_SERIAL=1 runs one drawio at a time, PlantUML and typst still side
# by side. nix build .#esdm-doc, the build of the CI, sets it.
DRAWIO_SERIAL ?=

# The revision make diff compares with, and how the diff names both
# versions: the old one by REV (a doc-<version> tag by its version), the new
# one by the version in meson.build.
REV ?= $(error set REV to the git revision to compare with: make diff REV=<rev>)
LABEL_OLD ?= $(patsubst doc-%,%,$(REV))
LABEL_NEW ?= $(VERSION)

VERSION ?= $(shell sed -n "s/^[[:space:]]*version: '\(.*\)',/\1/p" \
	../../meson.build 2>/dev/null | head -n 1)
SOURCE_DATE_EPOCH ?= $(shell $(GIT) log -1 --format=%ct 2>/dev/null)
ifneq ($(SOURCE_DATE_EPOCH),)
export SOURCE_DATE_EPOCH
endif
TYPST_INPUTS = --input version=$(VERSION)
# Released PDFs are PDF/A-2b for the archives of evaluations, the diffs
# are review aids. Typst refuses to write a PDF that does not conform.
PDFA = --pdf-standard a-2b

esdm_SRC := esdm.typ
esdm_presentation_SRC := presentations/esdm_presentation.typ
esdm_poster_SRC := poster/esdm_poster.typ
PDFS := $(OUT)/esdm-a4.pdf $(OUT)/esdm-letter.pdf \
	$(OUT)/esdm-a4-gray.pdf $(OUT)/esdm-letter-gray.pdf \
	$(OUT)/esdm_presentation.pdf $(OUT)/esdm_poster.pdf

# Where the QR code of the poster points.
POSTER_REPO_URL ?= https://github.com/smuellerDD/esdm

# The files whose changes make diff marks; all others - templates, plot
# code, data - are taken from the new version as they are.
DIFF_FILES := esdm.typ chapters/*.typ presentations/esdm_presentation.typ

# Chapters renamed since: an old version that still has the old name is
# diffed against it.
RENAMED := chapters/01-introduction.typ=chapters/introduction.typ \
	chapters/02-design.typ=chapters/design.typ \
	chapters/03-kernel-es-assessment.typ=chapters/kernel-es-assessment.typ \
	chapters/04-ebpf-assessment.typ=chapters/ebpf-assessment.typ \
	chapters/05-configurations.typ=chapters/configurations.typ \
	chapters/06-usage.typ=chapters/usage.typ \
	chapters/07-development.typ=chapters/development.typ

FIGURES := $(patsubst %.drawio,%.svg,$(wildcard figures/*.drawio)) \
	   $(patsubst %.puml,%.svg,$(wildcard figures/*.puml)) \
	   $(patsubst %.dot,%.svg,$(wildcard figures/*.dot)) \
	   figures/qr-repo.svg
# The histograms, rendered by R from plots/data, and kept apart from the
# figures: make diff renders the figures of old trees, which plot in Typst.
PLOTS := $(patsubst plots/data/%.csv,plots/%.svg,\
	   $(filter-out plots/data/meta.csv,$(wildcard plots/data/*.csv)))
# Their gray renderings, for the grayscale variant of the design document
GRAY_FIGURES := $(patsubst %.drawio,%.gray.svg,$(wildcard figures/*.drawio)) \
	   $(patsubst %.puml,%.gray.svg,$(wildcard figures/*.puml)) \
	   $(patsubst %.dot,%.gray.svg,$(wildcard figures/*.dot)) \
	   $(PLOTS:.svg=.gray.svg)

TYPST_SOURCES = $(shell find . -path ./$(BUILD) -prune -o \( -name '*.typ' \
	-o -name '*.bib' -o -name '*.csl' -o -name '*.csv' \
	-o -name '*.sublime-syntax' \) \
	-print)

# Compile $1 to $2 with $3 as the root and the options $4, failing on any
# output of typst: it prints nothing but errors and warnings.
define typst-compile
	@mkdir -p $(dir $2)
	$(TYPST) compile --root $3 --diagnostic-format short $(TYPST_INPUTS) $4 $1 $2 2>$2.log || { cat $2.log >&2; rm -rf $2 $2.log; exit 1; }
	@if grep -q . $2.log; then cat $2.log >&2; rm -rf $2 $2.log; exit 1; fi
	@rm -f $2.log
endef

.PHONY: all poster figures check-palette check-identifiers check-options diff \
	clean
.DELETE_ON_ERROR:

all: $(PDFS)

poster: $(OUT)/esdm_poster.pdf

figures: $(FIGURES)

check-palette:
	$(PYTHON) ../tools/check_palette.py .

# The meson options and ESDM functions the documentation names exist. It
# needs meson_options.txt and the C sources, which the nix build of the
# documentation does not have; CI runs it on the checkout.
check-identifiers:
	$(PYTHON) ../tools/check_identifiers.py ../..

# chapters/build-options-list.typ is generated from meson_options.txt.
check-options:
	$(PYTHON) ../tools/gen_meson_options.py --check ../..

CHECKS := check-palette
ifneq ($(wildcard ../../meson_options.txt),)
CHECKS += check-identifiers check-options
endif

ifneq ($(DRAWIO_SERIAL),)
# Each figure in the list waits for the one before it.
drawio-chain = $(if $(word 2,$1),$(eval $(word 2,$1): | $(word 1,$1))$(call \
	drawio-chain,$(wordlist 2,$(words $1),$1)))
$(call drawio-chain,$(patsubst %.drawio,%.svg,$(sort $(wildcard figures/*.drawio))))
endif

# drawio names the gradients of a figure with a random ID: the name of the
# figure in its place keeps the SVG, and so the PDFs, the same every build.
figures/%.svg: figures/%.drawio
	$(DRAWIO) $(DRAWIO_FLAGS) -o $@.tmp.svg $<
	sed 's/drawio-svg-[A-Za-z0-9_-]\{20\}-/drawio-svg-$*-/g' $@.tmp.svg >$@
	@rm -f $@.tmp.svg

figures/%.svg: figures/%.puml
	$(PLANTUML) -headless -tsvg -pipe <$< >$@

# Graphviz writes font-family="Source Sans 3" unquoted, which CSS rejects for
# a name with a number: quoted, or Typst falls back to its default font.
figures/%.svg: figures/%.dot
	$(DOT) -Tsvg $< | sed "s/font-family=\"\([^\"']*\)\"/font-family=\"'\1'\"/g" >$@

# The shorter stem makes make prefer this rule to the three above for them.
figures/%.gray.svg: figures/%.svg ../tools/gray_svg.py
	$(PYTHON) ../tools/gray_svg.py $< $@

plots/%.svg: plots/data/%.csv plots/data/meta.csv plots/histogram.R
	$(RSCRIPT) plots/histogram.R $* $@ plots/data

plots/%.gray.svg: plots/%.svg ../tools/gray_svg.py
	$(PYTHON) ../tools/gray_svg.py $< $@

# The QR code of the poster, in ink.
figures/qr-repo.svg:
	$(QRENCODE) -t SVG -m 0 --foreground=0F172A -o $@ '$(POSTER_REPO_URL)'

$(OUT)/esdm-a4.pdf $(OUT)/esdm-letter.pdf: $(OUT)/esdm-%.pdf: \
		$(FIGURES) $(PLOTS) $(TYPST_SOURCES) | $(CHECKS)
	$(call typst-compile,$(esdm_SRC),$@,.,$(PDFA) --input paper=$(subst letter,us-letter,$*))

# The grayscale variant: the palette in gray (input color=gray), the gray
# renderings of the figures.
$(OUT)/esdm-a4-gray.pdf $(OUT)/esdm-letter-gray.pdf: $(OUT)/esdm-%-gray.pdf: \
		$(FIGURES) $(PLOTS) $(GRAY_FIGURES) $(TYPST_SOURCES) | $(CHECKS)
	$(call typst-compile,$(esdm_SRC),$@,.,$(PDFA) --input color=gray --input paper=$(subst letter,us-letter,$*))

$(OUT)/esdm_presentation.pdf: $(FIGURES) $(PLOTS) $(TYPST_SOURCES) | $(CHECKS)
	$(call typst-compile,$(esdm_presentation_SRC),$@,.,$(PDFA))

$(OUT)/esdm_poster.pdf: $(FIGURES) $(PLOTS) $(TYPST_SOURCES) | $(CHECKS)
	$(call typst-compile,$(esdm_poster_SRC),$@,.,$(PDFA))

# The old version is this directory as of REV, extracted with git archive
# into $(BUILD)/old and given its figures by this Makefile. git archive runs
# in the top directory: in a subdirectory it would only archive what lies
# below it in the tree given. typstdiff.py merges the old version with the
# working tree into $(BUILD)/diff, whose documents show what was deleted
# struck through in red and what was inserted underlined in green, with
# change bars in the margin.
diff: $(FIGURES) $(PLOTS)
	rm -rf $(BUILD)/old $(BUILD)/old.tar $(BUILD)/diff
	mkdir -p $(BUILD)/old
	$(GIT) -C "$$($(GIT) rev-parse --show-toplevel)" archive --format=tar \
		-o "$(abspath $(BUILD))/old.tar" \
		'$(REV):'"$$($(GIT) rev-parse --show-prefix)"
	tar -x -f $(BUILD)/old.tar -C $(BUILD)/old
	$(MAKE) -C $(BUILD)/old -f $(CURDIR)/Makefile figures
	$(PYTHON) ../tools/typstdiff.py --old $(BUILD)/old --new . \
		--out $(BUILD)/diff --exclude '$(BUILD)' --exclude '*.pdf' \
		--label-old '$(LABEL_OLD)' --label-new '$(LABEL_NEW)' \
		$(foreach f,$(DIFF_FILES),--diff '$(f)') \
		$$(for p in $(RENAMED); do [ -e "$(BUILD)/old/$${p%%=*}" ] && \
			printf ' --pair %s' "$$p"; done)
	$(call typst-compile,$(BUILD)/diff/$(esdm_SRC),$(OUT)/esdm-diff.pdf,$(BUILD)/diff)
	$(call typst-compile,$(BUILD)/diff/$(esdm_presentation_SRC),$(OUT)/esdm_presentation-diff.pdf,$(BUILD)/diff)

clean:
	rm -rf $(BUILD) $(FIGURES) $(PLOTS) $(GRAY_FIGURES) $(PDFS) \
		$(OUT)/esdm-diff.pdf $(OUT)/esdm_presentation-diff.pdf
