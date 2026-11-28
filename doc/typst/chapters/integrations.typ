#import "../template.typ": *

= Integrations <sec:integrations>

This chapter addresses integrators. Applications draw random numbers from the
#ac("ESDM") through the libraries they already use – OpenSSL, Botan, libgcrypt –
and through the protocol of the #ac("EGD")\; #ac("HSM", pl: true) and
smart cards feed the #ac("ESDM") in the other direction. Figure
@fig:integrations shows how the libraries reach the #ac("ESDM") server; section
@sec:using-languages shows Rust and Python.

#figure(
  image("../figures/integrations.svg", width: 85%),
  caption: [How the libraries reach the #ac("ESDM"), and the one gate all their
    output passes],
) <fig:integrations>

== No Output Before the ESDM Is Seeded <sec:integration-gate>

None of the integrations returns a byte of the #ac("ESDM") before the
#ac("ESDM") is operational, for four reasons; the integrations that fall
back to the kernel by design are named below.

#paragraph[One gate in the server][Every random number a #ac("DRNG") of the
#ac("ESDM") generates comes
from `esdm_drng_get()` (`esdm/esdm_drng_mgr.c`), which refuses to produce
one while the #ac("ESDM") is not operational – its initial #ac("DRNG") not fully
seeded – or its self tests have not passed:]

```c
	if (!esdm_get_available() || !esdm_state_operational())
		return -EOPNOTSUPP;

	/*
	 * No bits are handed out unless the crypto implementations producing
	 * them are known to work: neither before the self tests ran nor after
	 * one of them failed.
	 */
	if (!esdm_selftest_crypto_passed())
		return -EOPNOTSUPP;
```

It checks the verdict of the self tests again after each generation and
wipes the chunk it generated if they failed in the meantime.

#paragraph[No generator of their own][The integrations run no #ac("DRNG") that
could produce output in the meantime: the instantiate and reseed operations
of the OpenSSL providers do nothing and every generate operation is one
request to the #ac("ESDM"), Botan's `ESDM_RNG` forwards every request, and
libgcrypt's pool fills from the socket only. The one exception, the seed
source provider of OpenSSL, feeds OpenSSL's own #ac("DRBG"), which produces
nothing before its seed source has delivered.]

#paragraph[Waiting instead of short answers][Before the #ac("ESDM") is
operational, the server answers a request of the full or the prediction
resistance path with `-EAGAIN`, and the #ac("RPC") client repeats it, backing
off from 1 to 16 ms, until the answer is complete. The #ac("EGD") server holds a
blocking read back until it can serve all of it. A caller receives its
whole request or an error, never a short or zeroed buffer; on an error, the
OpenSSL providers and the #ac("EGD") client wipe the buffer.]

#paragraph[No fallback][A provider or `ESDM_RNG` that cannot reach the
#ac("ESDM") fails the request instead of falling back to another generator –
otherwise pinning a library to the #ac("ESDM") would be advisory, not binding.
Only the `getrandom` shim and the #ac("CUSE") devices fall back to the kernel,
by design (table @tab:interfaces).]

#figure(
  table(columns: (auto, auto, 1fr, 1fr), align: left + horizon,
    table.header([Integration], [Interface], [#ac("ESDM", cap: true) not
    operational],
      [#ac("ESDM", cap: true) unreachable]),
    [OpenSSL #ac("RPC") providers], [#ac("RPC", cap: true)], [Waits], [OpenSSL
    error], [OpenSSL #ac("EGD") providers], [#ac("EGD", cap: true) 0x02], [Waits
    up to 60 s, then an error],
      [OpenSSL error],
    [Botan `ESDM_RNG`], [#ac("RPC", cap: true)], [Waits],
    [`Botan::System_Error`], [libgcrypt `rndegd`], [#ac("EGD", cap: true) 0x01,
    0x02], [Blocks], [Aborts the process], [`libesdm-getrandom.so`],
    [#ac("RPC", cap: true)], [Waits; `GRND_NONBLOCK`: `EAGAIN`],
      [Kernel `getrandom(2)`],
    [#ac("CUSE", cap: true) `/dev/random`], [#ac("RPC", cap: true)], [Waits],
    [Kernel device], [`esdm_cdev`], [#ac("EGD", cap: true) 0xeb], [Waits;
    `O_NONBLOCK`: `EAGAIN`],
      [`random` waits, `urandom` fails],
  ),
  caption: [What the integrations do while the #ac("ESDM") is not operational or
    cannot be reached],
) <tab:integration-gate>

#paragraph[Status queries][The OpenSSL providers report the state of the
#ac("ESDM") to `RAND_status()`: ready while it is fully seeded – operational for
the #ac("EGD") providers –, not ready before, and an error while it cannot be
reached. Botan's `is_seeded()` of `ESDM_RNG` returns true regardless. The gate
is the request, not the status query; a program that must not block on its
first request, or that gives up when `RAND_status()` reports not ready, is
started after the #ac("ESDM") is seeded, with `esdm-tool --wait-until-seeded` or the
boot gate of section @sec:usage-boot-gate.]

== OpenSSL <sec:integration-openssl>

Five OpenSSL 3 providers (meson option `openssl-rand-provider`,
`esdm-openssl-provider`(7)) answer OpenSSL's random number requests from
the #ac("ESDM"):

#figure(
  table(columns: (auto, auto, 1fr), align: left + horizon,
    table.header([Module], [Property], [Serves]),
    [`libesdm-rng-provider.so`], [`provider=esdm`], [#ac("RPC", cap: true): the
    full path,
      the prediction resistance path when OpenSSL asks for it],
    [`libesdm-rng-provider-pr.so`], [`provider=esdm`], [#ac("RPC", cap: true):
    always the
      prediction resistance path],
    [`libesdm-seed-src-provider.so`], [`provider=esdm`], [#ac("RPC", cap: true):
    only the seed
      source of OpenSSL's own #ac("DRBG")],
    [`libesdm-egd-provider.so`], [`provider=esdm-egd`], [#ac("EGD", cap: true)
    socket;
      refuses requests for prediction resistance],
    [`libesdm-egd-provider-pr.so`], [`provider=esdm-egd-pr`],
    [#ac("EGD", cap: true)
      prediction resistance socket],
  ),
  caption: [The OpenSSL providers of the #ac("ESDM")],
) <tab:openssl-providers>

The #ac("RPC") and #ac("EGD") providers register the four RAND algorithms of
OpenSSL – #ac("CTR")-, HASH- and #acs("HMAC")-#acs("DRBG") and SEED-SRC – and
route all of them to the #ac("ESDM"): the name an application asks for selects
no construction, as the data comes from the #ac("ESDM") in every case. The
configuration of section @sec:usage-reading replaces OpenSSL's #ac("DRBG")
chain; every `RAND_bytes()` and `RAND_priv_bytes()` is then a request to the
#ac("ESDM") of at most 256 bytes, as OpenSSL splits larger requests into
requests of this size. A
failed request puts `ESDM_R_RPC_FAILURE` or `ESDM_R_SHORT_RANDOM_DATA` on
OpenSSL's error stack, wipes the buffer and returns 0, which makes
`RAND_bytes()` fail.

The seed source provider keeps OpenSSL's own #ac("DRBG") running and only seeds
and reseeds it from the #ac("ESDM"):

```ini
[esdm_sect]
activate = 1
module = /usr/lib64/libesdm-seed-src-provider.so

[random_sect]
seed = SEED-SRC
seed_properties = provider=esdm
```

OpenSSL's primary #ac("DRBG") then blocks in its instantiation until the
#ac("ESDM") is operational, and generates nothing before it is instantiated.
Many small requests then do not each cost a request to the #ac("ESDM"), but
the output is that of OpenSSL's #ac("DRBG"): its claims apply, and the #ac("ESDM") only
provides its seed, from the full path or, when OpenSSL asks for prediction
resistance, from the prediction resistance path.

The #ac("EGD") providers need a single stream socket and no #ac("RPC") client,
which suits a chroot or a seccomp sandbox; section @sec:usage-egd-sandbox shows OpenSSH
on them. Every provider survives a `fork()`: the client libraries
reconnect in the child. The following commands show whether OpenSSL uses the
provider:

```sh
openssl list -random-generators
openssl rand -hex 32
```

== Botan <sec:integration-botan>

Botan 3.7.0 and later contain `Botan::ESDM_RNG`, a
`RandomNumberGenerator` drawing every request from the #ac("ESDM") over the
#ac("RPC") client library. It is a module of its own, built with
`./configure.py --enable-modules=esdm_rng`, and can be used wherever Botan takes
a `RandomNumberGenerator&` – key generation, #ac("TLS"), padding:

```cpp
#include <botan/esdm_rng.h>
#include <botan/hex.h>
#include <iostream>

int main()
{
	Botan::ESDM_RNG rng;            // full path; ESDM_RNG(true): PR path
	auto key = rng.random_vec(32);  // waits until the ESDM is operational
	std::cout << Botan::hex_encode(key) << "\n";
}
```

```sh
c++ -std=c++20 -o example example.cpp $(pkg-config --cflags --libs botan-3)
```

Every `randomize()` is one call of `esdm_rpcc_get_random_bytes_full`, or
`_pr` for `ESDM_RNG(true)`; a failure throws `Botan::System_Error`. Data an
application passes to `randomize_with_input()` or `add_entropy()` goes to
the #ac("ESDM") with `esdm_rpcc_write_data`, without entropy credit, so that it
can add to the state of the #ac("ESDM") but never weaken it. The instances of a
process share one connection; `Botan::esdm_rng()` returns a process-wide
instance.

Botan also serves as a crypto backend of the #ac("ESDM") itself
(`crypto_backend=botan`, Botan 3.2 or later, section @sec:backends): it
then provides the #ac("DRNG") – an #ac("HMAC") #ac("DRBG") with SHA-512 or, with
`botan_drng_type=chacha20`, Botan's ChaCha #ac("RNG") – and the hash inside the
server, behind the gate of section @sec:integration-gate. Botan's #ac("DRNG")
instances there have no seed source of their own: only the #ac("ESDM") seeds
them, and an unseeded instance throws an exception, which the #ac("ESDM")
reports as an error.

== libgcrypt and GnuPG <sec:integration-libgcrypt>

libgcrypt reads `getrandom(2)` by default, which `libesdm-getrandom.so`
redirects to the #ac("ESDM"). Built with `--enable-random=egd`, its standard
random number generator gathers from an #ac("EGD") socket instead
(section @sec:usage-egd):

```sh
./configure --enable-random=egd --with-egd-socket=/run/esdm-egd.socket
gpg --gen-random 2 32 | xxd      # GnuPG built against this libgcrypt
```

libgcrypt's gatherer `rndegd.c` asks with command 0x01 for what is
available, at most 255 bytes, and with command 0x02 for the rest, in chunks
of 255 bytes, until it has what it needs. It reads without a timeout; when
the connection ends, it connects again and aborts the process if that
fails. Before the #ac("ESDM") is operational, 0x01 comes back empty and 0x02 is
held back, so libgcrypt blocks: its pool cannot fill, and it hands out
nothing. An #ac("ESDM") that becomes unreachable causes the process to abort
instead of letting libgcrypt continue with less. Only libgcrypt's standard generator has an
#ac("EGD") path; its #ac("DRBG"), which it uses in #ac("FIPS") mode, and its
system generator read the kernel only.

== OpenSSH <sec:integration-openssh>

OpenSSH draws random numbers from two sources: OpenSSL for what it does
with libcrypto – #ac("RSA") and #ac("ECDSA") keys and signatures, #ac("ECDH")
over the #ac("NIST") curves, Diffie-Hellman – and `arc4random_buf()` for its own
primitives – the default key exchange `mlkem768x25519-sha256`, sntrup761,
Curve25519 and Ed25519 keys.

#paragraph[Through OpenSSL][An OpenSSL provider serves the former, set with
`OPENSSL_CONF` for `sshd` and `sshd-keygen`; `sshd` confines its children
with seccomp, so it needs the #ac("EGD") provider (section
@sec:usage-egd-sandbox). `sshd`, `ssh` and `ssh-keygen` check
`RAND_status()` when they start and exit unless it reports ready, which the
providers do only once the #ac("ESDM") is seeded: start them after it (section
@sec:usage-boot-gate):]

```ini
# systemctl edit sshd.service, and sshd-keygen.service where it exists
[Unit]
Requires=esdm-wait-until-fully-seeded.service
After=esdm-wait-until-fully-seeded.service

[Service]
Environment=OPENSSL_CONF=/etc/ssl/openssl-esdm-egd.cnf
```

#paragraph[`arc4random_buf()`][glibc provides it from version 2.36 on and
reads from the kernel internally, where neither a provider nor the shim nor
the #ac("CUSE") devices reach; only when built against a C library without it,
such as musl, does OpenSSH use its own implementation and seed it through
OpenSSL. A preloaded library could
replace glibc's function, but the key exchange runs in `sshd-auth`, whose
seccomp filter kills it on `socket(2)` and `connect(2)`, which an #ac("RPC")
client calls. On glibc, either let `esdm-kernel-seeder` seed the kernel
from the #ac("ESDM"), or restrict the key exchange to algorithms of OpenSSL:]

```sshd_config
# /etc/ssh/sshd_config.d/esdm.conf: ephemeral keys from OpenSSL's RAND
KexAlgorithms ecdh-sha2-nistp384,ecdh-sha2-nistp256
```

== strongSwan <sec:integration-strongswan>

charon asks its plugins for random numbers of three qualities: weak for
nonces and #ac("IV", pl: true), strong for session keys, true for key material.
Of the plugins offering at least the quality asked for, it takes the one of the
lowest quality and, among those, the first loaded – by default in the order
`rdrand`, `random`, `openssl`, `botan`. With `charon.load_modular = yes`,
the option `load` of a plugin switches it off (`no`) or raises its priority
(a number). Three plugins can take their random numbers from the #ac("ESDM")\;
`rdrand` loads before all of them and must therefore not be loaded.

#paragraph[`random`][It offers strong and true random numbers from two
files, which can be the devices of `esdm_cdev`: they wait until the #ac("ESDM")
is operational and never fall back to the kernel. It offers no weak ones; these
come from the next plugin, `openssl` or `botan`, which then needs the
#ac("ESDM") as well:]

```strongswan
# /etc/strongswan.d/charon/esdm.conf
charon {
    plugins {
        random {
            random = /dev/esdm_random
            urandom = /dev/esdm_urandom
            strong_equals_true = yes  # strong from random, the full path
        }
        rdrand {
            load = no
        }
    }
}
```

#paragraph[OpenSSL][The plugin `openssl` loads `openssl.cnf`, so the
provider configuration of section @sec:integration-openssl serves its weak
and strong random numbers and the key exchanges OpenSSL computes. It offers
no true ones; these come from `random` or `botan`. The configuration is set
for the unit:]

```ini
# systemctl edit strongswan.service
[Service]
Environment=OPENSSL_CONF=/etc/ssl/openssl-esdm.cnf
```

#paragraph[Botan][The plugin `botan` asks Botan for its random numbers by
name, which Botan 3.7 and later built with the module `esdm_rng` resolve to
`Botan::ESDM_RNG`: `esdm-full` for the full path, `esdm-pr` for the
prediction resistance path. It then serves all three qualities from the
#ac("ESDM"), and the key exchanges Botan computes; as it loads last, the other
plugins with random numbers are switched off:]

```strongswan
# /etc/strongswan.d/charon/esdm.conf
charon {
    plugins {
        botan {
            rng {
                strong = esdm-full  # weak and strong
                true = esdm-pr
            }
        }
        rdrand {
            load = no
        }
        random {
            load = no
        }
        openssl {
            load = no
        }
    }
}
```

#par(first-line-indent: 0pt)[`swanctl --list-algs` names the plugin
serving each quality.]

== The EGD Protocol <sec:integration-egd>

The #ac("EGD") sockets map the semantics of the protocol (section @sec:egd) onto
the gate:

#figure(
  table(columns: (auto, 1fr, 1fr), align: left + horizon,
    table.header([Command], [#ac("ESDM", cap: true) not operational],
    [Operational]), [0x01, 0xe0: read, non-blocking], [Empty answer], [Up to the
    requested
      bytes],
    [0x02, 0xe1: read, blocking], [Held back until complete], [The
      requested bytes],
    [0xe2: `/dev/urandom` read], [Empty answer], [The requested bytes],
    [0xeb: bulk read], [Empty answer], [As the read it names: 0x01, 0xe0 or
      0xe2],
    [0x03: write], [Inserted, credited for #ac("UID") 0 only],
      [Inserted, credited for #ac("UID") 0 only],
    [0xec: bulk insert], [Inserted, never credited],
      [Inserted, never credited],
  ),
  caption: [The #ac("EGD") reads and writes before and after the #ac("ESDM") is
    operational
  – 0xe0
    and 0xe1 from the prediction resistance #ac("DRNG")],
) <tab:egd-gate>

The server never blocks on a client: a held-back read parks its
connection, which processes no further command until it is answered, so
the answers keep their order, while the single #ac("EGD") worker serves the
other clients. A read that finds the #ac("ESDM") operational but its
#ac("DRNG", pl: true) waiting for a reseed is held back for at most a second
rather than answered empty, so that an
empty answer means "not operational". An unknown or malformed command
closes the connection. Clients are, besides libgcrypt and the OpenSSL
providers, `esdm_cdev` (section @sec:host-guest) and QEMU's `rng-egd`.

== Other Integrations <sec:integration-other>

`libesdm-getrandom.so`, preloaded with `LD_PRELOAD`, serves `getrandom(2)`
and `getentropy(3)` from the full path, with `GRND_RANDOM` from the
prediction resistance path, and with `GRND_NONBLOCK` returns `EAGAIN`
instead of waiting. The #ac("CUSE") `/dev/random` waits for the full path and
serves the prediction resistance path to readers that opened it with
`O_SYNC`. `esdm-kernel-seeder` waits for a full buffer before it credits
entropy to the kernel. Before the #ac("ESDM") is operational, the #ac("CUSE")
`/dev/urandom` and `getrandom(2)` with `GRND_INSECURE` serve the kernel
#ac("RNG"), as they promise output without waiting (table @tab:path-classes).

== Testing the Integrations <sec:integration-tests>

The #ac("EGD") server tests (`tests/egd`) check the behavior before the
#ac("ESDM") is
operational with a server of their own: the state reads "not operational",
0xe2, 0xe0 and every bulk read come back empty, a blocking read stays
unanswered, does not overtake a pipelined command and arrives once the
#ac("ESDM") is seeded, while other clients are served.
`tests/openssl-rand-provider` exercises every provider through `RAND_bytes()`
and `EVP_RAND`, with and without prediction resistance, and the #ac("EGD")
provider against a test peer, also with the peer gone. The machines `egd_gnupg`
and `egd_openssh` run GnuPG and OpenSSH on the #ac("ESDM"), and stop and restart
it: the consumers fail while it is stopped and recover once it runs again
(section
@sec:vm-tests). These tests start once the #ac("ESDM") is seeded; Botan's
`ESDM_RNG` has no test in the #ac("ESDM").

== Hardware Security Modules and Key Management Systems <sec:hsm>

An #ac("HSM"), a smart card or the random number generator of a key management
system feeds the #ac("ESDM") as an external entropy source (section
@sec:ext-es): a provider process of its own reads the device and serves its data
on a Unix domain socket, which `esdm-server --es_ext` reads. The vendor code
runs in the provider, with the privileges the device needs, never in the
#ac("ESDM")\; a crash of a provider affects only the provider itself. The
#ac("ESDM") server reads one external entropy source; figure @fig:hsm-provider
shows the providers that can take this role.

#figure(
  image("../figures/hsm-provider.svg", width: 100%),
  caption: [#ac("HSM", pl: true, cap: true), smart cards, key management systems
  and #ac("REST") services as
    the external entropy source – solid the default, dashed the
    alternatives],
) <fig:hsm-provider>

#paragraph[PKCS\#11][`esdm-es-pkcs11` serves any #acs("PKCS")\#11 token – an
#ac("HSM"), a #ac("USB") token, a smart card, SoftHSM – through
`C_GenerateRandom`. It binds the first slot with an initialized token that has a random number
generator, of the configured label if one is given, tests it on binding and on every self test of
the #ac("ESDM") (two reads must differ), and looks for a missing or failed token
again at most every 5 seconds. The #ac("PIN") comes from a file or a systemd
credential, never from the command line:]

```sh
meson setup build -Des_pkcs11=enabled -Des_pkcs11_entropy_rate=256
esdm-es-pkcs11 --module /usr/lib/pkcs11/vendor-hsm.so \
  --token_label RNG --pin_file /etc/esdm/hsm.pin \
  --socket /run/esdm-es-ext.socket --entropy_rate 256
esdm-server --es_ext /run/esdm-es-ext.socket
```

The unit `esdm-es-pkcs11.service` runs it under systemd, as the user
`esdm-es-pkcs11` on `/run/esdm-es-pkcs11/esdm-es-pkcs11.socket`\; the server
then needs `--es_ext /run/esdm-es-pkcs11/esdm-es-pkcs11.socket --es_ext_uid
esdm-es-pkcs11` (section @sec:tool-esdm-es-pkcs11).

#paragraph[Smart cards, YubiKey, Nitrokey][Two providers cover these
devices. Which of the two a device answers is best checked with the tools
of OpenSC before the #ac("ESDM") is configured:]

- Devices with a #acs("PKCS")\#11 module use `esdm-es-pkcs11`: a YubiKey with
  `libykcs11.so` of yubico-piv-tool or with `opensc-pkcs11.so`, a Nitrokey
  #ac("HSM") with `opensc-pkcs11.so`. The provider logs in only if the token
  asks for it; random numbers need no #ac("PIN") on most tokens.

  ```sh
  pkcs11-tool --module /usr/lib/libykcs11.so --generate-random 32 | xxd
  ```

- Cards answering the command GET CHALLENGE of ISO/IEC 7816-4 through
  `pcscd` use `esdm-es-pcsc`, without an application or a #ac("PIN"): most smart
  cards, and OpenPGP cards such as the Nitrokey Pro or Start.

  ```sh
  opensc-tool --send-apdu 00:84:00:00:10   # GET CHALLENGE, 16 bytes
  esdm-es-pcsc --socket /run/esdm-es-ext.socket --entropy_rate 256
  ```

#par(first-line-indent: 0pt)[`esdm-es-pcsc` declares no entropy rate:
configure the rate of the card's assessment, as above, or the #ac("ESDM")
credits its data with nothing. A request fails at once while another program
holds a transaction on the card – GnuPG's `scdaemon` holds OpenPGP cards
exclusively unless its option `pcsc-shared` is set. A certified chip with
a PTG.2 or PTG.3 generator allows the DRG.4 and PTG.3 configuration of
section @sec:drg4-ptg3.]

#paragraph[KMIP and REST][No provider is shipped for a key management system
over #ac("KMIP") or for a proprietary #ac("REST") interface; a small provider
built on `libesdm_es_ext` connects them (section @sec:writing-es-ext). Its
`get_entropy` must not block for long – a #ac("DRNG") waits for it – so the
provider fetches in the background, over the network, and answers from a
buffer: with #ac("KMIP") the operation #ac("RNG") Retrieve, with #ac("REST") the
vendor's call, both over mutually authenticated #ac("TLS"). An empty buffer
answers with an error, which the #ac("ESDM") credits with nothing:]

```c
/* get_entropy of a provider for a key management system: the data comes
 * from a buffer that a thread of the provider refills over KMIP or REST. */
static int kms_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
			   uint32_t *entropy_bits)
{
	struct kms_source *kms = ctx;

	if (kms_buffer_take(kms, buf, buflen))	/* not enough fetched yet */
		return -EAGAIN;			/* credited with nothing */

	/* the rate of the vendor's assessment of the RNG of the KMS */
	*entropy_bits = (uint32_t)(buflen * 8 * kms->rate / 256);
	return 0;
}
```

#paragraph[Crediting][The #ac("ESDM") credits a block with the claim of the
provider, at most at the rate it declares and capped by
`es_ext_entropy_rate`; `es_ext_peer_uid` names the only user besides root a
provider may run as, so that no other user can feed data credited as
entropy. Credit an #ac("HSM") or a key management system at the rate its
certification gives. The #ac("RNG") of an #ac("HSM") is typically a physical one
and so qualifies for DRG.4 (section @sec:physical-es). A key management system
reached over the network belongs to the security boundary of a DRT.1 tree
only when one operator runs both (section @sec:drt1).]

#paragraph[Without a provider][A daemon can also write the data into the
auxiliary pool: with the privileged #ac("RPC") call `esdm_rpcc_rnd_add_entropy`
or the #ac("IOCTL") `RNDADDENTROPY`, credited only for a caller with root
rights. The data then has no slot, no self test and no status of its own in the
#ac("ESDM")\; a provider is therefore preferable.]
