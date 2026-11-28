#import "../template.typ": *

= Build Options <sec:build-options>

This chapter lists every option of the meson build, in the groups of
`meson_options.txt`, with its type, its default and its description; `meson
configure` shows the same for a build directory. An option is set when the
build is configured or changed later:

```sh
meson setup build -Dcrypto_backend=openssl -Des_cpu_entropy_rate=0
meson configure build -Dais2031_ntg1=true
```

A feature takes `enabled` or `disabled`, a boolean `true` or `false`, an
integer a number in its range, a combo one of its choices. Entropy rates are
in bits per 256 bits of data; 0 keeps a source in use without crediting it.
Several options decide a compliance claim – the entropy rates, `sp80090c`,
`fips140`, `ais2031_*`, the reseeding limits; chapter @sec:configurations
gives the combinations that meet a standard, and section @sec:examples
complete command lines. Some options only set defaults: the server's command
line overrides the paths of the #ac("EGD") sockets and of the external entropy
source (section @sec:tool-esdm-server), and the privileged #ac("RPC") calls
override the entropy rates and the reseed interval at run time.

The reference below is generated from `meson_options.txt` by
`doc/tools/gen_meson_options.py`; its check (`make check-options` in
`doc/typst`, run by #ac("CI")) fails when the two differ.

#include "build-options-list.typ"
