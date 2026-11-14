# Build the ESDM documentation from its Typst sources.
#
#   make                  the design document and the slide deck as PDF
#   make figures          only render the draw.io and PlantUML figures to SVG
#   make clean
#
# Needs typst, plantuml and drawio (run under xvfb-run when there is no
# display; drawio-headless of nixpkgs does that on its own). With all of
# these and the fonts from nixpkgs:
#
#   nix build .#esdm-doc                  the PDFs
#   nix develop .#doc                     a shell to run make in
#
# A Typst warning fails the build. The documents are written to OUT (this
# directory by default). The SVGs of the figures are rendered next to their
# sources and are not tracked by git.

TYPST ?= typst
PLANTUML ?= plantuml
ifeq ($(DISPLAY)$(WAYLAND_DISPLAY),)
DRAWIO ?= xvfb-run -a drawio
else
DRAWIO ?= drawio
endif

# The light theme gives fixed colours instead of CSS light-dark() ones. The
# sources use plain (html=0) labels, as Typst does not render the
# foreignObject of HTML labels.
DRAWIO_FLAGS ?= -x -f svg --theme light --embed-svg-fonts false -b 1

OUT ?= .

# Every drawio and plantuml run is a process of its own that takes seconds
# to start: render the figures side by side, on all CPUs unless make was
# given -j. drawio-headless gives each run an X display and a configuration
# directory of its own, so they do not get in each other's way.
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 4)
endif
MAKEFLAGS += --output-sync=target

DOCS := esdm esdm_presentation
esdm_SRC := esdm.typ
esdm_presentation_SRC := presentations/esdm_presentation.typ

FIGURES := $(patsubst %.drawio,%.svg,$(wildcard figures/*.drawio)) \
	   $(patsubst %.puml,%.svg,$(wildcard figures/*.puml))

TYPST_SOURCES = $(shell find . \( -name '*.typ' -o -name '*.bib' \
	-o -name '*.csl' -o -name '*.csv' \) -print)

# Compile $1 to $2 with $3 as the root, failing on any output of typst:
# it prints nothing but errors and warnings.
define typst-compile
	@mkdir -p $(dir $2)
	$(TYPST) compile --root $3 $1 $2 2>$2.log || { cat $2.log >&2; rm -f $2 $2.log; exit 1; }
	@if [ -s $2.log ]; then cat $2.log >&2; rm -f $2 $2.log; exit 1; fi
	@rm -f $2.log
endef

.PHONY: all figures clean
.DELETE_ON_ERROR:

all: $(foreach d,$(DOCS),$(OUT)/$(d).pdf)

figures: $(FIGURES)

# drawio names the gradients of a figure with a random ID: the name of the
# figure in its place keeps the SVG, and so the PDFs, the same every build.
figures/%.svg: figures/%.drawio
	$(DRAWIO) $(DRAWIO_FLAGS) -o $@.tmp.svg $<
	sed 's/drawio-svg-[A-Za-z0-9_-]\{20\}-/drawio-svg-$*-/g' $@.tmp.svg >$@
	@rm -f $@.tmp.svg

figures/%.svg: figures/%.puml
	$(PLANTUML) -headless -tsvg -pipe <$< >$@

$(OUT)/%.pdf: $(FIGURES) $(TYPST_SOURCES)
	$(call typst-compile,$($*_SRC),$@,.)

clean:
	rm -f $(FIGURES) $(foreach d,$(DOCS),$(OUT)/$(d).pdf)
