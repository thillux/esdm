// The acronyms of the design document, tracked with acrostiche: #ac("X")
// gives the long form at the first use and the short form after it,
// #ac("X", pl: true) the plural, #ac("X", cap: true) a capitalized long
// form at the start of a sentence. #acs("X") gives the short form without
// counting as a use, for compounds such as "ESDM-internal". Headings and
// run-in paragraph titles name acronyms in plain text: a use there would
// expand the acronym in the table of contents and the running header.
//
// Names of classes and constructions - DRG, DRT, NTG, PTG, RBGC - and of
// products, companies and CPU instructions are no acronyms here.

#import "@preview/acrostiche:0.7.0" as acrostiche

#let acronym-defs = (
  "ABI": "application binary interface",
  "ACVP": "Automated Cryptographic Validation Protocol",
  "ACVTS": "Automated Cryptographic Validation Testing System",
  "AES": "Advanced Encryption Standard",
  "AIS": "Anwendungshinweise und Interpretationen zum Schema",
  "API": "application programming interface",
  "APT": "adaptive proportion test",
  "BPF": "Berkeley Packet Filter",
  "BSD": "Berkeley Software Distribution",
  "BSI": "Bundesamt für Sicherheit in der Informationstechnik",
  "BTF": "BPF Type Format",
  "CAVP": "Cryptographic Algorithm Validation Program",
  "CET": "Control-flow Enforcement Technology",
  "CMVP": "Cryptographic Module Validation Program",
  "CI": "continuous integration",
  "CPU": "central processing unit",
  "CSR": "control and status register",
  "CTR": "counter mode",
  "CUSE": "character device in user space",
  "DF": "degrees of freedom",
  "DMI": "Desktop Management Interface",
  "DRBG": "deterministic random bit generator",
  "DRNG": "deterministic random number generator",
  "eBPF": "extended Berkeley Packet Filter",
  "ECDH": "elliptic curve Diffie-Hellman",
  "ECDSA": "Elliptic Curve Digital Signature Algorithm",
  "EGD": "Entropy Gathering Daemon",
  "ES": "entropy source",
  "ESDM": "Entropy Source and DRNG Manager",
  "FIPS": "Federal Information Processing Standard",
  "FUSE": "Filesystem in Userspace",
  "GCD": "greatest common divisor",
  "GPL": "GNU General Public License",
  "GUI": "graphical user interface",
  "HID": "human interface device",
  "HMAC": "keyed-hash message authentication code",
  "HSM": "hardware security module",
  "HTML": "Hypertext Markup Language",
  "HTTPS": "Hypertext Transfer Protocol Secure",
  "HWRAND": "hardware random number generator",
  "I/O": (long: "input/output", long-pl: "inputs/outputs"),
  "ICMP": "Internet Control Message Protocol",
  "ID": "identifier",
  "IG": "Implementation Guidance",
  "IID": "independent and identically distributed",
  "IOCTL": "input/output control",
  "IPC": "inter-process communication",
  "IR": "Internal Report",
  "IRQ": "interrupt request",
  "IV": "initialization vector",
  "JSON": "JavaScript Object Notation",
  "KMIP": "Key Management Interoperability Protocol",
  "KVM": "Kernel-based Virtual Machine",
  "LFSR": "linear feedback shift register",
  "LRNG": "Linux Random Number Generator",
  "LSB": "least significant bits",
  "LTO": "link-time optimization",
  "MSB": "most significant bits",
  "NIST": "National Institute of Standards and Technology",
  "NPTRNG": "non-physical true random number generator",
  "NUMA": "non-uniform memory access",
  "OS": "operating system",
  "OSR": "oversampling rate",
  "PC/SC": "Personal Computer/Smart Card",
  "PID": "process identifier",
  "PIE": "position-independent executable",
  "PIN": "personal identification number",
  "PKCS": "Public-Key Cryptography Standards",
  "POSIX": "Portable Operating System Interface",
  "PR": "prediction resistance",
  "PRNG": "pseudorandom number generator",
  "PTRNG": "physical true random number generator",
  "RBG": "random bit generator",
  "RCT": "repetition count test",
  "RCU": "read-copy-update",
  "RELRO": "relocation read-only",
  "REST": "representational state transfer",
  "RNG": "random number generator",
  "RPC": "remote procedure call",
  "RPM": "RPM Package Manager",
  "RSA": "Rivest-Shamir-Adleman",
  "SHA": "Secure Hash Algorithm",
  "SHAKE": "Secure Hash Algorithm Keccak",
  "SP": "Special Publication",
  "SSD": "solid-state drive",
  "SSH": "Secure Shell",
  "TLS": "Transport Layer Security",
  "TPM": "Trusted Platform Module",
  "TRNG": "true random number generator",
  "TSC": "time stamp counter",
  "TSS": "TPM Software Stack",
  "UID": "user identifier",
  "URL": "uniform resource locator",
  "USB": "Universal Serial Bus",
  "UUID": "universally unique identifier",
  "vDSO": "virtual dynamic shared object",
  "VM": "virtual machine",
  "VMM": "virtual machine monitor",
  "XDRBG": "XOF-based deterministic random bit generator",
  "XOF": "extendable-output function",
  "XOR": "exclusive or",
)

// True while the lists of figures and tables are set: they repeat the
// captions, and a use there would count before the text.
#let in-lists = state("esdm-acronyms-in-lists", false)

#let ac(key, pl: false, cap: false) = context {
  if in-lists.get() {
    acrostiche.display-short(key, plural: pl)
  } else {
    acrostiche.acr(key, plural: pl, cap: cap)
  }
}

#let acs(key, pl: false) = acrostiche.display-short(key, plural: pl)

#let init-acronyms() = acrostiche.init-acronyms(acronym-defs)

// The list of all acronyms, alphabetical, as a term list like the
// glossary: the grid of acrostiche's print-index() is lost in the HTML. It
// holds the acronyms of the figures, the algorithm names (SHA-256) and the
// license text as well, which use no #ac(): define an acronym only if the
// document uses it.
#let acronym-index() = {
  let long(v) = if type(v) == str { v } else { v.long }
  terms(..acronym-defs.pairs()
    .sorted(key: p => lower(p.at(0)))
    .map(((k, v)) => terms.item(k, long(v))))
}
