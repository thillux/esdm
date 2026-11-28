// Inputs of doc/typst/Makefile shared by all documents: the version of
// meson.build, and the date of the build, which the Makefile and nix pin to
// the last commit (SOURCE_DATE_EPOCH) for reproducible output.
#let esdm-version = sys.inputs.at("version", default: "(unversioned)")
#let doc-date = datetime.today().display(
  "[month repr:long] [day padding:none], [year]")
