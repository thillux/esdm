#import "template.typ": *

#show: esdm-doc.with(
  title: [Entropy Source and DRNG Manager],
  authors: (
    ("Stephan Müller", "smueller@chronox.de"),
    ("Markus Theil", "theil.markus@gmail.com"),
  ),
  date: [ESDM #esdm-version \ #doc-date],
  abstract: [
    Almost all parts of cryptography rest on a random number generator
    which produces data that are indistinguishable from a perfect generator.
    This also implies that the random number generator is seeded with
    sufficient entropy and the entropy is maintained during processing. Also
    a reseed at proper intervals is important to maintain the security
    strength. Finally, different users and use cases have different
    requirements regarding seeding and the deterministic processing. All
    these tasks are non-trivial in nature. The #ac("ESDM") provides a
    flexible and extensible framework. The #ac("ESDM") also provides a set
    of well-known interfaces: an #ac("API") and #ac("ABI") compliant
    drop-in replacement for Linux /dev/random, /dev/urandom and
    getrandom(2) system call as well as for an #ac("EGD").
  ],
)

#include "chapters/introduction.typ"

#part[Design and Assurance]
#include "chapters/design.typ"
#include "chapters/kernel-es-assessment.typ"
#include "chapters/ebpf-assessment.typ"
#include "chapters/configurations.typ"
#include "chapters/hardening.typ"
#include "chapters/formal-verification.typ"
#include "chapters/interface-specification.typ"

#part[Manual]
#include "chapters/building.typ"
#include "chapters/build-options.typ"
#include "chapters/usage.typ"
#include "chapters/tools.typ"
#include "chapters/integrations.typ"
#include "chapters/development.typ"
#include "chapters/testing.typ"

#show: appendix
#include "chapters/appendix.typ"
#include "chapters/ais2031-requirements.typ"
