Changes 1.2.4
* Add an optional EGD (Entropy Gathering Daemon) protocol interface to the
esdm-server, enabled by starting esdm-server-egd.socket or with
--egd_socket <path>, which serves legacy entropy consumers such as libgcrypt's
rndegd backend or OpenSSL's RAND_egd()

* Add libesdm_egd_client, a client library for the EGD interface, and
libesdm-egd-provider.so, an OpenSSL 3 RAND provider based on it: both need
nothing but the one EGD socket and therefore work where the RPC interface
cannot be reached, OpenSSH's sandboxed pre-authentication child included

* EGD interface: ESDM-specific commands on the same socket for what the EGD
protocol cannot express - prediction resistance reads (0xe0, 0xe1), reading
without waiting for full seeding (0xe2), the state (0xe3), the status as text
and JSON (0xe4, 0xe5), and, for a peer with UID 0 only, crediting entropy,
clearing the entropy count, reseeding and setting write_wakeup_threshold and
urandom_min_reseed_secs (0xe6 - 0xea); codes far from the standard ones, so
EGD clients are unaffected. libesdm_egd_client offers the prediction resistance
reads (esdm_egd_client_get_random_pr), libesdm-egd-provider.so serves OpenSSL's
prediction resistance requests with them and libesdm-egd-provider-pr.so all
requests

* EGD interface: reads beyond the 255 bytes of one transfer cost a round trip
per 64 KiB rather than per 255 bytes - libesdm_egd_client sends the commands of
a blocking read at once, the esdm_cdev module the commands of up to 64 KiB and
takes the answers in bulk, and the esdm-server answers a run of the same read
command with one response, the esdm-egd-net-server and -relay a run of blocking
reads with one read of their backend. The EGD server reads the coarse
monotonic clock for its timeouts, and the DRNGs for their reseed interval,
which a clocksource without a vDSO serves without a system call.
egd_net_bench (meson test --benchmark) measures the EGD socket, the RPC
interface and egd-net, esdm-cdev-check throughput the devices of the module

* Add the EGD protocol over the network (meson option egd-net): the
esdm-egd-net-server serves the EGD protocol of the ESDM on TCP and answers it
through the unprivileged RPC interface, so nothing of the network reaches the
esdm-server and every client is unprivileged - entropy claims are dropped, the
privileged commands answered -EPERM; the esdm-egd-net-relay serves the EGD
socket of a host without an ESDM, where libgcrypt, RAND_egd() and the EGD
OpenSSL provider find it, from such a server. Two modes: TLS 1.3 with mutual
authentication by certificates (egd-net-tls, by the TLS stack of OpenSSL,
GnuTLS or Botan), and plain TCP, which is neither encrypted nor authenticated
and meant only for networks protected underneath, by IPsec or WireGuard, say -
it has to be asked for with --plain, is never a default and builds with every
crypto backend. Bounds on the connections in all, on probation and per source
address, per client - certificate, or source address with IPv6 grouped by /64
in plain mode -, an idle and a handshake timeout, and an allowlist of source
networks (--allow); systemd units with socket activation, DynamicUser= and the
TLS files as credentials, on port 7378 (egd-net-port)

* EGD over the network: certificates, trust anchors and CRLs are taken up
without a restart, on SIGHUP and when the files change (--reload_interval),
by a complete new context that replaces the old one only if everything loaded,
so a broken rotation keeps the service up; the relay's upstream connections
take up a rotated client certificate the same way. CRLs (--crl) are checked
identically on every TLS stack, within its verification and with the alert
of the reason, on the chain up to the own trust anchors, and fail closed for
the certificate of the peer (--crl_check_all for the CA certificates,
--crl_allow_expired for an expired CRL); delta CRLs and CRLs with an issuing
distribution point are refused. Established connections are checked against
reloaded CRLs and closed when revoked, connections of an expired client
certificate closed, and CRLs close to or past their nextUpdate logged;
esdm-egd-net-crl-update@.timer downloads CRLs without an HTTP client in the
daemons

* EGD over the network: TLS 1.3 takes the algorithms of BSI TR-02102-2 alone,
with every TLS stack - the conventional ones it recommends and the hybrid key
exchange it allows, no algorithm of post-quantum cryptography on its own:
the suites TLS_AES_256_GCM_SHA384 and TLS_AES_128_GCM_SHA256 (and
TLS_AES_128_CCM_SHA256 with GnuTLS), the key exchange by the hybrid of ML-KEM
SecP384r1MLKEM1024 ahead of secp384r1, secp256r1, secp521r1, the curves of
Brainpool, ffdhe3072 and ffdhe4096, signatures by ECDSA and RSA-PSS, and
certificates on RSA of 3072 bits and more or on elliptic curves of 256 bits
and more. Neither X25519, X448, ffdhe2048, ChaCha20-Poly1305, EdDSA nor
signatures with SHA-1 are offered or accepted, nor ML-KEM alone, nor a hybrid
whose conventional half falls short of 192 bits (X25519MLKEM768,
SecP256r1MLKEM768); a certificate on ML-DSA, EdDSA or DSA among the own
certificate, its chain and the trust anchors fails the start, one in the
chain of a peer the handshake. The hybrid comes with OpenSSL 3.5, GnuTLS
built with leancrypto and Botan 3.8; a TLS stack without it, or a peer
without it, keeps to the conventional groups. The debug log tells whether the
TLS stack has the hybrid, and the group of each connection. es-ext-net, on
the same TLS 1.3, has all of it

* EGD and external entropy sources over the network: several CAs are trusted
at once, for the rollover of a CA - --ca may be given up to 8 times to the
esdm-egd-net-server and -relay, the esdm-es-ext-relay and every provider
program, ca_files of struct esdm_egd_client_net_config and struct
esdm_es_ext_server_net_config name the files next to ca_file, and a file
added, dropped or changed is taken up with the next reload, as the other TLS
files are; a certificate of either CA is taken, see esdm-egd-net-server(8)

* libesdm_egd_client: network modes - esdm_egd_client_alloc_net() with an
extensible configuration, plain TCP, which keeps the syscall discipline of the
Unix domain socket once connected, and TLS, by a module of the library loaded
by the first client in TLS mode, so that a process using it otherwise has no
TLS stack loaded - and the ESDM commands
esdm_egd_client_get_random_unseeded(), esdm_egd_client_get_state(),
esdm_egd_client_status() and esdm_egd_client_status_json() in every mode

* Add the kernel module esdm_cdev (kernel/esdm_cdev): /dev/esdm_random,
/dev/esdm_urandom and /proc/esdm served from the ESDM over its EGD socket, with
the ioctls of the kernel's random devices - the counterpart of the CUSE
frontend in the kernel, leaving the kernel's own devices untouched; it falls
back to the kernel's RNG while the ESDM is not reachable

* esdm_cdev: the checks of the module are esdm-cdev-check (tests/esdm_cdev), a
C program in place of the Python script of the 1.2.4 development versions:
meson test runs those that hold next to the ESDM of the machine (suite
esdm_cdev) where the module is loaded and skips them elsewhere, the build option
esdm-cdev-check installs the program with its man page, and the VM test of the flake runs every
check with it, without Python; the checks include that the reads waiting for
the ESDM wait for an ESDM not operational, and the credit of writes

* Add esdm-vhost-user-rng (meson option vhost-user-rng, Linux only): the
vhost-user back-end of a virtio entropy device, giving QEMU (vhost-user-rng-pci,
and vhost-user-rng on virtio-mmio, e.g. on microvm) and Cloud Hypervisor
(--generic-vhost-user ...,device_type=rng) guests a virtio-rng device served
from the fully seeded DRNG of the ESDM - nothing before the ESDM is fully
seeded -, or with --pr from the prediction resistant one, optionally rate
limited (--max_bytes/--period_ms) - with --pr to 1024 bytes per second unless
--max_bytes says otherwise, as every 32 bytes reseed the prediction resistant
DRNG. One process per VM without privileges, as it
parses memory the guest writes, reaching the ESDM over the unprivileged RPC
interface; every field of the queue is read once, chains, indirect tables and
buffers are checked against the queue size and the memory of the guest, and a
malformed request is completed with nothing written. Socket activated through
the template units esdm-vhost-user-rng@.socket/@.service
(/run/esdm-vhost-user-rng/<vm>.sock, group of the meson option
vhost-user-rng-socket-group, kvm by default), see esdm-vhost-user-rng(8); no
live migration (QEMU declares vhost-user-rng unmigratable), no packed ring

* Split the build option ais2031 into ais2031_ntg1 (NTG.1 seeding strategy),
ais2031_drg3 (DRG.3 class) and ais2031_drg4 (DRG.4.10 reseeding limits), which
can now be selected independently - ais2031_drg3 and ais2031_drg4 are mutually
exclusive

* Add the build option ais2031_drg3: it applies the entropy source oversampling of
the sp80090c option without the request size based reseeding limits of DRG.4,
which are not brought back by setting sp80090c alongside; the status reports the
AIS 20/31 DRG classes the build satisfies (a DRG.4 build reports DRG.3 as well)

* NTG.1 seeding strategy: seed from the jitter RNG alone when it is operated in
its own NTG.1 mode (es_jent_ntg1 with jitterentropy >= 3.7.0), as it is NTG.1
conformant without a second entropy source, once it delivered the full seed
entropy

* Add eBPF-based scheduler and interrupt entropy sources (es_sched_ebpf,
es_irq_ebpf): no kernel patches required, in-program SP800-90B health tests,
zeroization of every collected raw sample when the sources are unloaded - the
in-program collection buffers and the ring buffer holding the events included -
raw entropy measurement tooling including the SP800-90B restart test in
tests/es_ebpf_testing

* Centralize asynchronous buffer management to collect entropy from slow entropy sources

* Add TPM2 entropy source

* Add the PKCS#11 entropy source esdm-es-pkcs11 (meson option es_pkcs11): a provider of its own serving the random number generator of a PKCS#11 token, read with C_GenerateRandom through libp11, on a Unix domain socket the ESDM reads through one of its ExternalSocket sources (esdm-server --es_ext_socket /run/esdm-es-pkcs11/esdm-es-pkcs11.socket --es_ext_socket_uid esdm-es-pkcs11) - neither libesdm nor esdm-server load a PKCS#11 module or link libp11; it takes the token of --token_label, or the first one with a random number generator, from the module of --module, logs in only if a PIN is configured and the token asks for a login, never tries a PIN the token refused again, looks for a token that is lost or not there yet at most every 5 seconds - loading the module anew where its slots hold none -, tests a token whenever it is bound, declares "PKCS#11" and the token label as the name and es_pkcs11_entropy_rate (or --entropy_rate) as the rate of the source, and reports the module, the token label, the token and its slot, whether it is present and logged in to, the PIN state and the last error in its status; the PIN is the first line of a file (--pin_file) or the systemd credential pkcs11-pin (--pin_credential), never an option or a build setting; esdm-es-pkcs11.service runs it as the system user esdm-es-pkcs11 of a sysusers.d file, sandboxed, with ImportCredential=pkcs11-pin and the options of ESDM_ES_PKCS11_OPTIONS, ordered before esdm-server.service, which passes ESDM_SERVER_OPTIONS on to the server; see esdm-es-pkcs11(8)

* Add external entropy sources: noise sources developed outside of the ESDM, served by a provider process the ESDM reads over a Unix domain socket with a documented protocol (ExternalSocket ES: esdm-server --es_ext_socket, meson option es_ext_socket_path; the provider has to run as root or as the user of --es_ext_socket_uid / es_ext_socket_peer_uid) - the ESDM loads no code of a source into its own process; a block is credited with the entropy the source claims, capped by the rate of the source - the one configured with es_ext_socket_entropy_rate, --es_ext_socket_entropy_rate or esdm_config_es_ext_socket_entropy_rate_set(), else the one the provider declares in its answer to INFO, capped at 256, else 0; the status shows the rate as "entropy_rate" and its "entropy_rate_source", and auto configures none -, with nothing while the source fails or claims more than the block holds, and with nothing after a failed self test until a self test passes; the ES monitor finds out on its own when a failed source delivers again; a build has es_ext_socket_num provider socket sources (meson option, 1 to 16, 1 by default - a build without any disables es_ext), each an entropy source of its own with its own provider, rate, accepted user and state - ExternalSocket as the one source, ExternalSocket0, ExternalSocket1, ... with several -, configured by the i-th entry of the comma separated meson options (a single rate or uid for all sources), by the n-th occurrence of the esdm-server options and by the libesdm calls esdm_es_ext_socket_set_path(), esdm_es_ext_socket_set_peer_uid() and esdm_config_es_ext_socket_entropy_rate[_set](), which take the index of the source first; a source declares its name in the answer of its provider to the INFO request of the socket protocol, asked once per connection, and the ESDM shows the source under it in the "name" member of its status and in its log, keeping the name of its entry - ExternalSocket, or ExternalSocket0, ExternalSocket1, ... with several - as its "instance"; a name that is no 1 to 32 bytes of UTF-8 without control characters, or that of another entropy source, is refused, and a provider older than INFO is connected to again without asking

* Add libesdm_es_ext (esdm_es_ext.h, libesdm_es_ext(3)), the library a provider is developed against: the callbacks of a source - struct esdm_es_ext_plugin with init, fini, get_entropy, selftest, status_json and entropy_rate, the latter called after init -, the provider server serving them on a Unix domain socket (esdm_es_ext_server_*()), and esdm_es_ext_provider_main(), the whole main() of a provider program: it takes the command line of a provider - --socket, --mode, --client_uid (root and nobody served by default, nobody else), --no_dtls, --name and --entropy_rate declaring a name and a rate in place of those of the callbacks, -v, and the options of the network -, sets the source up and serves it until SIGTERM or SIGINT, telling systemd when it is ready; the example in es-ext/example is such a program, and esdm-es-pkcs11 is one with the options of its token next to the common ones; several providers run as several processes, each on a socket of its own

* Incompatible with the 1.2.4 development versions, which loaded an external entropy source into the ESDM as a plugin library as well: the ExternalLib entropy sources, esdm-server --es_ext_lib and --es_ext_lib_entropy_rate, the meson options es_ext_lib_num, es_ext_lib_path and es_ext_lib_entropy_rate, esdm_config_es_ext_lib_entropy_rate[_set]() and esdm_es_ext_lib_set_path() of libesdm, esdm_es_ext_plugin_load(), esdm_es_ext_plugin_unload(), struct esdm_es_ext_plugin_handle, ESDM_ES_EXT_PLUGIN_SYMBOL and ESDM_ES_EXT_PLUGIN_EXPORT of libesdm_es_ext, and esdm-es-ext-serve, which served a plugin library, with its man page and its units esdm-es-ext-serve-net.socket/.service are removed - an external entropy source is served by a provider process only, read over the provider socket of an ExternalSocket source: a struct esdm_es_ext_plugin of its callbacks - the name kept, as providers are built against it - and a main() returning esdm_es_ext_provider_main(), which takes the command line esdm-es-ext-serve had but --plugin; a provider on the network is a program of the site's making, with units of its own (libesdm_es_ext(3) shows a pair); es_ext_socket_num is 1 at least; libesdm and libesdm_es_ext keep their soversion, as everything removed was new in 1.2.4

* Add external entropy sources on the network (meson option es-ext-net, Linux
only, with the TLS stack of OpenSSL, GnuTLS or Botan): the provider server of
libesdm_es_ext - and with it every provider program, esdm-es-pkcs11 included -
serves on TCP with --listen or socket activation
(esdm_es_ext_server_alloc_net()), and the new esdm-es-ext-relay on the host of
the ESDM serves a local provider socket the ESDM reads as any ExternalSocket
source and forwards INFO, SELFTEST, GET_ENTROPY and STATUS one to one, checked
as the ESDM checks them, so the esdm-server keeps leaving the network
namespace and parses no certificate. TLS 1.3 from the first message on, the
messages of the Unix domain socket inside with the length of each part in
front, with mutual authentication by certificates and the checks of the server
name, the CRLs (--crl, --crl_check_all, --crl_allow_expired), the rotation on
SIGHUP and file change and the post-quantum key exchange and certificates of
egd-net, shared with it. The provider bounds its connections in all, in their
handshake, per source address and per client certificate, in time, and by an
allowlist of source networks (--allow), and tells "tcp" as its "transport" and
the SHA-256 of the client certificate as its "peer" in its status; the relay
answers INFO with an errno while the provider is not reachable and bounds
every step upstream below the timeout of the ESDM (--timeout_ms). Unit
esdm-es-ext-relay.service (system user esdm-es-ext-relay, which the ESDM
accepts with --es_ext_socket_uid), connecting to port 7379 (es-ext-net-port)
by default; see esdm-es-ext-relay(8) and NETWORK in libesdm_es_ext(3)

* es-ext-net: TLS 1.3 on TCP instead of DTLS 1.2 on SCTP with SCTP-AUTH -
incompatible with the 1.2.4 development versions: a provider listens, and the
relay connects, on TCP, neither needs the kernel module sctp, a firewall
passes TCP to port 7379, and the status tells "tcp" as the "transport"; the
algorithms are those of egd-net now, the hybrid key exchange of ML-KEM, which
DTLS 1.2 had no place for, included

* Incompatible with the 1.2.4 development versions, whose PKCS#11 entropy source was part of the ESDM: esdm-tool --pkcs11-pin and --pkcs11-token-label, esdm-server --pkcs11_module, esdm_rpcc_set_pkcs11_config[_int]() of libesdm_rpc_client, esdm_config_es_pkcs11_entropy_rate[_set]() of libesdm and the meson options es_pkcs11_pin and es_pkcs11_entropy_blocks are removed - the module, the token label and the PIN are configuration of esdm-es-pkcs11, and es_pkcs11_module_path, es_pkcs11_token_label and es_pkcs11_entropy_rate are its defaults; the slot of the RPC call stays as RpcReservedSetPkcs11Config, which the server answers with -EOPNOTSUPP, so that the calls after it keep their index on the wire

* External entropy sources: a provider can report a JSON status of its own - the STATUS request of the socket protocol; the ESDM accepts a JSON object of at most 1024 bytes (ESDM_ES_EXT_PROTO_STATUS_MAX) from a provider, and shows it as the "provider" member of the ExternalSocket ES status, skipping it rather than waiting while the source is read; any provider served by libesdm_es_ext answers STATUS with {"server": {...}, "plugin": ...}, fields of its own - version, plugin_api, the name and the entropy_rate it declares, dtls of the connection, clients, client_slots, requests, the selftest verdict, uptime_seconds - next to the status the callback status_json of its source reports, a JSON object of at most 512 bytes, which is null for a source without one, a failing one, one that is no valid JSON object and one that does not fit

* Add opportunistic DTLS to the connections between the processes of the ESDM (meson option dtls, disabled by default): DTLS 1.2 of the TLS stack of the crypto backend - OpenSSL, GnuTLS or Botan - with an ephemeral key exchange keyed with a pre-shared key built into the ESDM, unauthenticated, protecting the data against reading on the socket path rather than the peer's identity; a client asks for it on every new connection and goes on in the clear with a server that does not know or refuses it, so old and new clients and servers keep working together
  * RPC: both interfaces of esdm-server, the RPC client library and with it the getrandom(2) shim, which uses the kernel instead while the DTLS itself asks for random numbers; esdm-server --no_dtls serves in the clear only; at most 64 encrypted connections per unprivileged user and 256 per worker
  * External entropy sources: the ExternalSocket ES asks the provider for it (STARTDTLS request of the protocol), which the provider server of libesdm_es_ext agrees to, and a provider program with --no_dtls refuses

* DTLS of the connections: ECDHE with a pre-shared key built into the ESDM - the identity "esdm-opportunistic-dtls" and its SHA-256, a constant of every build and no secret, as the DTLS stays unauthenticated - instead of ECDHE-ECDSA with an ephemeral self-signed server certificate, on curves of 256 bits of security and with AES-256, in cipher suites both NIST SP 800-52r2 and BSI TR-02102-2 allow: TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (RFC 8442) on brainpoolP512r1 between two builds with Botan, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 with Encrypt-then-MAC on secp521r1 with OpenSSL and GnuTLS, which have no ECDHE-PSK suite with AES-GCM, and between them and Botan; X25519, P-256, ChaCha20-Poly1305 and AES-128 are no longer negotiated, and a CBC session without Encrypt-then-MAC is refused (by an OpenSSL server, a GnuTLS and a Botan peer); the key exchange is not post-quantum, as ML-KEM is defined for TLS 1.3 and none of the TLS stacks has DTLS 1.3; incompatible with the DTLS of the 1.2.4 development versions - the handshake between them fails, and the client goes on in the clear on a new connection

* DTLS and TLS: one backend per TLS stack (common/tls/esdm_tls_openssl.c, esdm_tls_gnutls.c, esdm_tls_botan.cpp, see esdm_tls_backend.h) serves the local DTLS of the connections and the TLS with certificates of egd-net and es-ext-net alike - one set-up of the library, one error mapping and one connection, differing per transport in the protocol, the suites, the groups and how the socket is reached -, in place of a DTLS backend of its own per TLS stack; libesdm and the client libraries take the core of it only, without the code of the certificates. The local DTLS negotiates what it did, and: no TLS stack retransmits a flight of its handshake any more - OpenSSL did after a second, GnuTLS gave up after a minute -, a record a Botan peer could not send at once is sent with the next call instead of being lost, a GnuTLS peer sends the alert of a failed handshake, and esdm_dtls_want() tells POLLOUT when the DTLS waits for the socket to take a record

* DTLS and TLS: a secure minimal mode, set up in one place per TLS stack for every transport - no session cache, no tickets of TLS 1.2 or TLS 1.3 issued or asked for, no pre-shared key of resumption, no early data (0-RTT), no renegotiation either way (OpenSSL: the legacy one with an old server neither; GnuTLS and Botan end a connection whose peer asks for one), no post-handshake authentication, no compression, no heartbeat -, and the local DTLS requires the extended master secret (RFC 7627) of every peer, next to Encrypt-then-MAC for CBC: a session without either is refused. A client of Botan still sends an empty session_ticket extension in the ClientHello of DTLS 1.2, and a server of GnuTLS or Botan a session ID nothing keeps, which neither TLS stack lets leave out. The tests read the handshakes off the wire - two connections between the same contexts, each a full handshake, no NewSessionTicket after the handshake of TLS 1.3

* Add an optional io_uring event loop to the RPC server (meson option rpc-io-uring, disabled by default, Linux only, liburing >= 2.2 found with pkg-config): each worker thread waits for the events of its connections with an io_uring of its own instead of an epoll instance - a one-shot poll per connection, armed again in the system call that waits for the next round, so that what a round leaves unread is reported again as by the level-triggered epoll; the requests are read and written as before, by the DTLS of a connection where it has one. A worker falls back to epoll, logging it once, where io_uring cannot be set up (a kernel without it, kernel.io_uring_disabled, a seccomp filter such as that of a container), and esdm-server --no_io_uring waits with epoll; the SystemCallFilter=@system-service of esdm-server.service allows io_uring. Measured with rpc_bench on an AMD Ryzen 9 5950X with Linux 7.2 - 1 to 64 clients of 32 byte requests, with and without DTLS - the two loops serve within a few percent of each other, io_uring 2-5% behind in throughput beyond one client in the clear and spending up to 1.3 us more server CPU per request, as both wait for readiness and read and write the requests alike

* Map each worker of the unprivileged RPC interface and of the EGD interface of esdm-server to a node DRNG (esdm_drng_node_bind() of libesdm): RPC worker i to node i + 1, EGD worker i to the last node minus i, wrapping around past node 0, whose initial DRNG nobody is mapped to; a request of a mapped worker goes to its node DRNG straight away, without the read lock over the node array and without probing the other DRNGs, and is served as before - by the first free fully seeded node DRNG, the initial one only if none is - while its node DRNG is not fully seeded, being reseeded or at its maximum output without full reseed. No DRNG is added: the node DRNGs are seeded, reseeded and reported as before, and the prediction resistant requests stay with the prediction resistance DRNG. esdm-server --no_fixed_drng_mapping serves the workers as every other caller. Measured with rpc_bench on 8 cores of an AMD Ryzen 9 5950X for the server and 8 for the clients, 32 byte requests without fips140: up to 27% more requests per second with 2 to 4 clients of the epoll loop and 16% with 4 EGD clients, a lower p99 latency with 16 clients of the io_uring loop (65 against 87 us) at the same throughput, otherwise within the run-to-run spread; with fips140 the throughput stays bound by the reseeds of the DRNGs either way

* Kernel Jitter RNG ES: the kernel crypto API RNG it reads is configurable - meson option es_jent_kernel_name (jitterentropy_rng by default) and esdm-server --es_jent_kernel_name, e.g. for a jitterentropy kernel module registering its RNG under another name; the status names it

* Entropy pools: each auxiliary pool and the conditioning pool of the eBPF entropy sources is an XDRBG-256 - the XDRBG over SHAKE256 with a state of 512 bits - instead of a pair of conditioning hashes; whatever is inserted is the seed of the next reseed and an extraction reseeds and generates; the SHAKE256 is that of the crypto backend (nettle >= 3.6 for the GnuTLS backend, Botan >= 3.2), the crypto self test covers it with a known-answer test of the XDRBG, and esdm_get_digestsize() reports the size of the state

* Kernel module esdm_es: the DRBG post-processing the interrupt and scheduler entropy sources is the XDRBG-256 of the ESDM (esdm/crypto/esdm_xdrbg.c, the one of the auxiliary pools), compiled into the module and operated on the SHAKE256 of the kernel's SHA-3 library, on every kernel that has it (CONFIG_CRYPTO_LIB_SHA3, selected e.g. by CONFIG_CRYPTO_SHA3, which Linux 7.2 and later require); its known-answer test runs when the module is loaded; the HMAC_DRBG the module carried for Linux 7.2 and later is gone; a kernel without the SHA-3 library uses the HMAC_DRBG with SHA-512 of the kernel crypto API as the only one, so the module parameter esdm_drbg_type, which selected the Hash_DRBG or the CTR_DRBG instead, is gone

* Status: the status is built as JSON only, the entropy sources report their state as a JSON object, and every text status - esdm_status(), RPC, shared memory, CUSE, esdm-tool - is the JSON status printed as text; numbers are JSON numbers, the eBPF ES reports a permanent health test failure as a member of its own, and the ExternalSocket ES no longer reports "root0" for a provider accepted only as root

* The shell scripts of the repository run with set -euxo pipefail and bash

* The source tree of the library is sorted into esdm/es, esdm/crypto,
esdm/drng and esdm/status

* The kernel modules moved from addon/linux_esdm_es and addon/linux_esdm_cdev to kernel/esdm_es and kernel/esdm_cdev and are built from the source tree, sharing code with the ESDM instead of carrying copies: the IOCTL interface of /dev/esdm_es (kernel/shared/esdm_es_ioctl.h) with the interrupt and scheduler entropy sources, the security strength, the SP800-90C oversampling and the seed sizes making up the entropy buffers that interface hands over (kernel/shared/esdm_seed_sizes.h), the cutoffs of the SP800-90B health tests (kernel/shared/esdm_health_cutoffs.h) with the eBPF entropy sources, the XDRBG-256 with the auxiliary pools, and the EGD protocol (service-egd/esdm_egd_protocol.h) of esdm_cdev with the EGD interface

* The test tooling moved from addon to tests, named after the meson options
building it: the validation helpers esdm-getrawentropy and esdm-extractlsb
from addon/test to tests/validation-helpers, the raw entropy measurement
tooling of the eBPF entropy sources (esdm-ebpf-collect and its analysis
scripts) from addon/es_ebpf_testing to tests/es_ebpf_testing. The installed
tools are unchanged.

* The design document and the presentation are Typst sources with their figures
as draw.io, PlantUML and Typst plot sources (doc/typst, nix build .#esdm-doc),
brought in line with the code; the presentations before v1.0.0 are dropped

* SP800-90C compliance: all ES with zero entropy are inserted into DRBG as "additional info" or "personalization string" (compliance to section 2.6)

* SP800-90C / AIS 20/31 DRG.4.10: with sp80090c, ais2031_drg4 or fips140 (unless combined with ais2031_drg3) the bits a DRNG may produce without a full reseed are capped at 2^17 (drng_max_reseed_bits), and the reseed is triggered at three quarters of that limit (drng_reseed_threshold_bits capped at 98304 bits instead of 2^16) - reseeding dominates the throughput, so this gains 13-16% while leaving 32768 bits of output for the asynchronous reseed of a node DRNG to complete in - under sustained load not enough: the node is then spent until the worker reseeds it in its next pass

* fix: esdm_get_seed() hands back the output of all entropy sources again, the zero-entropy ones collected as additional data included, without clearing the entropy estimates of the creditable sources; the returned entropy count covers the creditable sources only

* Reseed the DRNGs proactively: an asynchronous worker reseeds a DRNG whose interval elapsed whether or not data was ever requested from it, brings up instances that never reached the fully seeded level, spreads the seed times over a random offset and sleeps until the next reseed falls due; the status reports the worker, its passes and the time left before each reseed

* fix: An RPC client decoded a response whose header it had just rejected, handing the caller a payload reaching past the receive buffer - for the random calls, data generated for an earlier request (found by the new fuzz harnesses)

* fix: An interrupted RPC call left its answer on the connection, where it was handed out as the reply to the next call and every call after it; the connection is now dropped when a call abandons its answer (found by the new fuzz harnesses)

* fix: The OpenSSL RAND providers stored a new context lock over the old one when locking was enabled twice, leaking it and leaving the users of the shared context locking different things (found by the new fuzz harnesses)

* fix: Linux kernel addon: the requested entropy and the entropy rate set with ESDM_IRQ_CONF / ESDM_SCHED_CONF belong to the descriptor of /dev/esdm_es they are set on. Kept for the whole module, an ESDM crediting a source with nothing - the default for the scheduler ES - had the source deliver nothing to every other ESDM, and one crediting it had the source credited for the others

* Add fuzz harnesses for the RPC requests, responses and wire codec, the server as a client reaches it, both sides of the EGD interface and the library API (build option 'fuzzing', see tests/fuzz/README.md); beyond crashes they check what the code promised, and when building with -Dfuzzing=enabled their seeds are additionally replayed as regression tests by the ordinary test suite (meson test), also without libFuzzer

* Add a fuzz harness per shipped OpenSSL RAND provider module (build option 'openssl-rand-provider'), each loading its provider the way libcrypto does and holding it to the contract of <openssl/core_dispatch.h>

* Add fuzz harnesses for the vhost-user control messages and the request ring of esdm-vhost-user-rng, with memory regions to map and control messages between taking a request and completing it; beyond crashes they check that replies are framed as the request has it, that no file descriptor leaks, that nothing is written to guest memory outside the buffers the guest offered, and that used elements stay within the queue

* Add a stress test of the RPC request path under concurrent load, every request carrying an ID the answer has to carry back

* FIPS 140 integrity test: a missing HMAC file is now a failed integrity test rather than a pass; the reference values are written at installation time with esdm-tool (see README.usage.md)

* FIPS 140 integrity test: attest every component of the module - the ESDM library, the Jitter RNG and the crypto library of the selected backend - and not only the executable

* Run the self tests of the hash and the DRNG implementation every 10 minutes, and hand out random bits only while their outcome, reported in the status, is that they passed

* Add a self test to every entropy source and run them in the same pass as the crypto ones, at start up and on the interval; a failing source is logged and reported but does not stop the ESDM, as it stops being credited on its own

* Run the self tests on demand over the privileged RPC socket (esdm_rpcc_selftest, esdm-tool --selftest), answered with the state of both test groups and how many entropy sources were tested and failed

* DRBG self tests: use CAVP records that reseed, so instantiate, reseed and generate are all covered as SP800-90A section 11.3 and FIPS 140-3 IG 10.3.A require

* Self tests: accompany every known answer test with two negative tests, so that neither a comparison that cannot fail nor an implementation ignoring its input passes as a self test

* esdm-tool: add --max-reseed-secs SECS to set the maximum interval between two DRNG reseeds

* Add the status as a JSON document next to the human-readable text: esdm_status_json() in libesdm, the RPC call esdm_rpcc_status_json() and esdm-tool --status-json; the ESDM properties are members, the entropy sources an array below "entropy_sources" (json-c is a new build dependency)

* Status report: add one section per DRNG instance - seeding state, reseed counters, seed generation and the time of the last seeding - to the status text and to the JSON document ("drngs" array), carrying the initial and the prediction resistance instance; an instance is identified by type and node now, so the "id" member is gone

* Status reports are no longer truncated silently: a report that does not fit into the buffer is answered with -EMSGSIZE, a JSON document empty and a text report as far as it got, so esdm_status() returns a value now

* Add an RPC call to obtain the status of a single DRNG instance as JSON, addressed by the node it serves or by asking for the prediction resistance instance

* esdm-tool: add --drng-status [=NODE|pr] and --drng-status-json [=NODE|pr] to print one DRNG instance or, without an argument, all of them as a JSON array

* libesdm: export only the supported API, versioned by a linker version script (symbol versions LIBESDM_1.0 for the API of esdm.h and esdm_config.h, LIBESDM_PRIVATE_1.0 for in-tree consumers); every other DSO_PUBLIC symbol is hidden

* libesdm_rpc_client, libesdm_egd_client and libesdm_aux_client: export only the functions their installed headers declare, versioned by linker version scripts - the thread pool of the common library they link is no longer exported, and the logger only in a private node of the RPC and the aux client, where the ESDM frontends linking them interpose their own; every function of 1.2.3 an installed header declares is still exported. The OpenSSL RAND providers export nothing but OSSL_provider_init, so the EGD client linked into the EGD providers no longer binds to a libesdm_egd_client.so of the application loading them

* Add man pages for esdm-server, esdm-tool, the CUSE daemons, esdm-proc, esdm-kernel-seeder, esdm-server-signal-helper, esdm-ebpf-collect, esdm-getrawentropy, esdm-extractlsb, the OpenSSL providers and the libesdm, libesdm_rpc_client, libesdm_egd_client, libesdm_getrandom and libesdm_aux_client libraries

* esdm-server and the CUSE daemons no longer fork into an isolating PID namespace by default; pass --pid_namespace to enable it (without it, the IPC resources stay in place at exit, as the daemon has dropped the privileges to remove them, and the next start replaces them)

* CPU ES: retry RDSEED up to 1024 times with PAUSE in between, as it underflows routinely under load, and retry transient RNDRRS failures on aarch64 the same way; a read failure no longer disables the CPU ES for the lifetime of the daemon, it is credited with no entropy until the next successful read

* CPU ES: on s390, only use PRNO-TRNG when the facility list and the PRNO query report it, instead of dying with SIGILL on hardware without it (pre-z14)

* Add a test that assesses 1 MiB of ESDM output with the SP800-90B non-IID estimators (ea_non_iid, skipped when not installed) and requires more than 6 bits of min-entropy per byte

* Add a thread sanitizer build (nix build .#esdm-tsan) running the test suite

* fix: data race on the job pointer of the worker thread slots (found by the thread sanitizer)

* fix: SHA-3 on big-endian machines: the aligned input path absorbed host-endian lanes, so the digest depended on the alignment of the input and the known-answer self tests failed

* fix: CUSE: a fallback read returning 0 bytes made the read loop spin forever; it now fails with -EIO

* fix: CUSE: writes at a non-zero file offset to the proc tunables read the wrong bytes of the payload

* fix: getentropy() of libesdm_getrandom returned -EIO for requests above 256 bytes instead of -1 with errno set

* fix: status shared memory: access the mapping through an atomic pointer so that a concurrent detach is not dereferenced, do not remove the segment at exit while CUSE daemons are still attached, and do not destroy and recreate the live IPC on esdm_reinit(), which stranded attached CUSE daemons on an orphaned mapping and unlinked semaphores

* fix: RPC client use-after-free when esdm_rpcc_fini_service() ran concurrently with a call, and a double free with two concurrent reallocating esdm_rpcc_init_*() calls

* fix: Linux kernel addon: the boot-time raw entropy capture overwrote its first sample, the read pointer of the per-CPU rings was published before the DRBG consumed the data, letting the producer overwrite it mid-hash, the block size guard compared bytes with bits, and a reset scrubbed only the online CPUs, so events of an offline CPU were credited after a VM fork or an SP800-90B failure

* fix: esdm-proc: /proc/sys/kernel/random/uuid read empty; a fresh UUID is now generated on every open, like the kernel's

* fix: OpenSSL backend: the additional data from the uncredited entropy sources was dropped on every reseed instead of entering the DRBG as additional input

* fix: Jitter RNG ES: a failed startup health test went unnoticed, and the Jitter RNG was credited regardless; when its collector could not be set up either, the initialization of the whole ESDM failed instead of continuing without the Jitter RNG

* fix: without a reseed worker (esdm_init() without esdm_init_monitor()), node DRNGs were never reseeded; a request now reseeds them itself

* fix: RPC server: a new connection could be closed as idle before its first request was read; the client now also retries an unprivileged request once on a fresh connection when the server closes it without an answer

* fix: RPC and EGD servers: running out of file descriptors made the workers spin on the listening socket; they stop accepting until a connection closes or the idle timer fires

* fix: worker threads were cancelled asynchronously, which can strike in the middle of malloc(), the logger or a DRNG reseed holding its locks; cancellation is deferred now

* fix: esdm.spec: package the EGD client library and the EGD OpenSSL providers

* fix: DRNG manager: index the per-node DRNGs by the allocated array, so raising the node limit after the allocation no longer reads or frees past its end

* fix: a prediction resistance request no longer drops all DRNGs out of the seeded state; esdm_get_seed() could return nothing afterwards

* fix: SP800-90C: the prediction resistance DRNG counts as fully seeded only with the additional 64 bits of RBG3(RS) and withholds them from its output

* fix: only the seeding of the initial DRNG makes the ESDM operational, not that of any node DRNG

* fix: with a reseed interval of zero the initial DRNG was seeded twice per request

* fix: the auxiliary pool reports the digest size of its conditioning hash instead of the maximum

* fix: a failed Jitter RNG initialization no longer zeroes its configured entropy rate, so a later successful reinitialization is credited again

* fix: esdm_init() tears down what it set up when it fails; the timing entropy source rate setters are serialized; the start-up rate check counts every entropy source

* fix: RPC server: all server threads run in the isolating mount, cgroup and network namespaces, not only the main thread (a PKCS#11 module reaching a network HSM over TCP needs the network namespace switched off)

* fix: RPC server: the self test is refused to unprivileged clients; a response that cannot be packed is answered with a failure; a connection whose answer cannot be written is dropped instead of stalling the worker per request; a worker thread that cannot be started is noticed

* fix: RPC client: a past poll timeout no longer suppresses the reconnect after a broken connection

* fix: libesdm_getrandom: getrandom() with GRND_NONBLOCK returns EAGAIN while the ESDM is not seeded, and the library drops only the RPC client reference it took

* fix: CUSE: a non-blocking read that would block returns EAGAIN; the privileged ioctls require CAP_SYS_ADMIN instead of UID 0, as the kernel does; a negative RNDADDTOENTCNT is refused; 32 bit callers are served; the status ioctl serves a complete report only; a failed privilege drop ends the daemon instead of leaving it running as root

* fix: esdm-proc: every file's content is generated per open, so concurrent readers no longer share one buffer

* fix: esdm-kernel-seeder: refuse an interval outside 1 to INT32_MAX seconds

* fix: Linux kernel addon: convert entropy rates in 64 bit arithmetic

* fix: leancrypto backend: additional input beyond the 84 bytes the XDRBG accepts is condensed with SHA3-512 - leancrypto >= 1.9 refused the seed, so no DRNG was ever seeded; the hash init result is checked where leancrypto returns one

* fix: the DRBG sanity health check seeds the DRBG first, so its limit checks are reached; the Hash DRBG state is locked into memory; SHA-2 wipes its message schedule with memset_secure

* fix: logger: the log file is no longer closed at exit under a thread still writing to it; threading: the thread and parent of a worker slot are read atomically when signaling

* fix: esdm_safe_read()/esdm_safe_write() return the bytes transferred before a later error

* fix: a DRNG seed serves exactly ESDM_DRNG_RESEED_THRESH generate requests - the request that ran the counter out triggered the reseed and was counted against the old seed, so one fewer was served

* Jitter RNG ES: with jitterentropy >= 3.8.0 the known answer tests of its conditioning component run through jent_selftest() bound to the synchronous and the asynchronous collector, a collector that failed them serves nothing, and a failed periodic self test empties the block cache

* fix: the DRG.4 / SP800-90C limit of bits generated without a full reseed is enforced per block rather than once per request, so a large request no longer runs past it while the reseed is pending; a node DRNG that reached the limit hands out what it generated so far and the rest of the request is served by the initial DRNG while it has output left; a DRNG left over the limit is no longer used for the rest of the request; the PR DRNG reaching it no longer clears the all-nodes-seeded state

* fix: a seed the init DRNG rejected no longer makes the ESDM fully seeded and operational

* fix: auxiliary pool: the hash states are replaced under the pool lock as a whole on reinit; choosing the pool to read no longer counts the oversampling twice

* fix: the shared block cache of the asynchronous entropy sources discards a block whose fill started before a reset; the Jitter RNG ES falls back to its synchronous collector instead of serving a 0 bit block while credited

* fix: eBPF entropy sources: events collected before a failed health test, still in flight in the ring buffer or a per-CPU batch, are no longer credited; the pending events are counted per reset generation and health epoch, so they are reported correctly after a reset or a failure

* fix: Linux kernel addon: a wrapped ring is hashed only as far as it is consumed, instead of crediting the tail again; no extraction before the internal DRBG exists (division by zero); the ring reset is serialized with the extraction and safe against concurrent producers; runtime entropy rates are floored at the configured module parameter; a failed module init removes the testing interface, and a missing debugfs disables only the testing interface; a reset between the blocks of one extraction discards the whole extraction; unloading waits for in-flight hook callbacks (all hook patches)

* fix: esdm-server exits with an error when the RPC or EGD interfaces cannot be set up, instead of 0, and no longer waits forever for an unprivileged interface that failed to start; the idle timeout is honored to the microsecond

* esdm-server: an unprivileged peer is limited to min(max(512, 16 per online CPU), half the RLIMIT_NOFILE) RPC and 256 EGD connections, and EGD connections idle for 60 seconds are closed when their slots or descriptors are wanted, so a local user can no longer exhaust the connections or file descriptors of the server; the unprivileged RPC connections are bounded in total as well, leaving descriptors for the EGD interface, and once every worker is full, a worker closes the least recently active connection - an idle one before one whose answer is unread - preferring the UID holding the most, to make room for a new one - many UIDs of one user (subordinate UIDs) no longer lock out other users

* fix: RPC client: a forked child only closes the inherited sockets instead of shutting down the connections the parent still uses (which made the parent resend requests); a server that does not answer is given up on instead of retried forever; a privileged request is not sent again after the server closed the connection, as it may already have been applied; a status report truncated to the maximum message size is delivered with -EMSGSIZE, and the JSON status calls leave the buffer empty on any server error

* Add esdm_rpcc_get_random_bytes_pr_nonblock(): getrandom(GRND_RANDOM|GRND_NONBLOCK) and O_NONBLOCK|O_SYNC reads of the CUSE devices no longer wait for a busy prediction resistance DRNG but fail with EAGAIN

* fix: getrandom wrapper: invalid flags fail with -1 and errno EINVAL as the system call does; the kernel fallback no longer passes GRND_FULLY_SEEDED

* fix: esdm-server: --username takes its argument

* fix: esdm-server-signal-helper: the exit status reflects the requested mode alone, exactly one of --suspend/--resume is required, and only the PID named by a PID file the server still holds locked is signaled

* fix: CUSE: the caller of a privileged ioctl is checked before any lock is taken, reading /proc with file system root credentials of the checking thread alone, so it works with /proc mounted hidepid and a refused caller cannot stall other requests; privileged ioctls are refused with EAGAIN until the device is set up; the daemon stays in the mount namespace holding its bind mounts, so they are removed from the host at exit ("mnt" removed from RestrictNamespaces=); --pid_namespace is documented and warned about to refuse the privileged ioctls

* fix: esdm-proc: writing a value that is not a number fails with EINVAL; esdm-tool wipes the seed when writing it out fails

* fix: threading: a cancelled worker releases the locks it holds and is always joined; the logger can no longer be cancelled in the middle of a record, which left every later log call and the exit hanging

* fix: ChaCha20 DRNG: the key is replaced at least every GiB of output of one request; the locked states of the ChaCha20 and the Hash DRBG own their pages, so freeing one no longer unlocks another, and an exhausted memlock budget no longer fails the allocation

* fix: GnuTLS backend: hash init resets the state and the self test checks every step; Botan backend: the HMAC DRBG is instantiated over the seed and the personalization string in one step, covered by its known answer test

* fix: FIPS integrity test: the HMAC file parser rejects characters that are not hex and logs why, tolerates trailing white space and blank lines, and reports a file without a reference value

* fix: meson: fips140 implies the complete SP800-90C build configuration, reseeding limits and disabled entropy source caches included - except for the reseeding limits when combined with ais2031_drg3

* fix: the maximum bits without full reseed is clamped to INT_MAX, as a larger value silently disabled the limit; the RPC client bounds the resubmission of a request by time rather than by attempts, independent of client-rx-tx-timeout-exponent; esdm_drbg_zero_free() unlocks the state memory

* EGD server: served by one worker thread per online CPU, at most four, each serving the clients it accepted, so a request waiting for a DRNG reseed no longer holds up every other EGD client; the workers run in thread slots reserved for them rather than in the shared pool

* fix: esdm_rpcc_get_random_bytes() sends a request again that the ESDM answered with -EAGAIN - the DRNG serving it reached its maximum output without full reseed - at once and, should that be answered the same way, after the poll interval, as esdm_rpcc_get_random_bytes_full() does; a blocking read of /dev/urandom no longer fails with EAGAIN

* fix: a request no longer seeds a node DRNG that is not fully seeded in the caller's thread while the ESDM is operational - it is served by another node or the initial DRNG, and the reseed worker brings the node up; before, every request did, under the pool lock, for as long as a spent node DRNG could not be fully reseeded, which stalled the EGD server and serialized the RPC workers

* fix: esdm-server and the CUSE daemons keep a non-dumpable state across their privilege changes - changing the IDs reset it to fs.suid_dumpable, which silently re-enabled core dumps of a server started with --memlock under systemd's default of 2; in sanitizer builds the root-only dumpable state is turned into the non-dumpable one, so LeakSanitizer can check the daemons at exit instead of aborting

* fix: RPC server: a worker thread failing while serving (epoll setup, epoll_wait() or registering a client) takes the server down with that error instead of silently leaving it with fewer workers; esdm_locked_mem_alloc() no longer reports success with a NULL pointer when mlock() fails without errno; the CUSE /proc reader refuses buffers too small for content and NUL; errno is only evaluated after calls that set it (found by the clang static analyzer)

* hardening: zero all used registers on return (-fzero-call-used-regs=used instead of used-gpr); pass the code generation hardening flags to the link as well, as LTO builds silently dropped -fzero-call-used-regs

* ci: build and test the default configuration without fips140 next to the FIPS builds; flake: nixosConfigurations are provided without a system level (nix flake check passes), and esdm-plain builds the esdm package without fips140 and sp80090c - and so without the SP800-90C configuration they imply - and runs the test suite on it

* fix: esdm.spec names the jitterentropy packages as openSUSE ships them

* fix: esdm.spec requires the protobuf-c runtime instead of protobuf

* flake: provide the FIPS integrity reference values of the ESDM, the jitter RNG and Botan, and of the build tree in the coverage VMs; update nixpkgs; build against the jitterentropy master (3.8.0) and libkcapi master, whose RNG tests are adjusted to Linux 7.2+; support Linux 7.2 and 7.3 in the kernel addon; hook patches for every vanilla kernel nixpkgs packages - 6.1, 6.6, 6.12, 6.18, 7.2 and 7.3 - each applying without fuzz; the kernels are enumerated from nixpkgs like jitterentropy-library does, linux_testing included; the ESDM kernels keep nixpkgs' own kernel patches instead of replacing them; CI builds the module and boots its VM test for every one of them

* fix: NTG.1 seeding strategy: the emergency seeding no longer loops forever under the pool lock when the only delivering source cannot fully seed the DRNG alone (e.g. the CPU ES with a failed jitter RNG)

* fix: the prediction resistance DRNG gives out nothing until its instantiation succeeded, instead of generating from a DRNG instantiated with too little entropy

* fix: library requests over 4 GiB no longer fail with -EFAULT; esdm-server and libesdm share one thread pool state, so the stack size and the teardown state the server sets reach the parallel entropy source fetch

* fix: the kernel RNG's entropy rate is reduced while an eBPF interrupt or scheduler ES is active, as it is for the kernel-based ones, instead of crediting the same interrupt timings twice; an eBPF ES with entropy rate 0 stirs in its events uncredited instead of never reading them, and is no longer treated as an SP800-90B source

* fix: the PKCS#11 and TPM2 entropy sources recover from a transient failure, retrying at most every 5 seconds, instead of staying disabled until the ESDM is reinitialized

* fix: the asynchronous block cache serves no entropy from an uncredited source and is discarded on a failed reinitialization; the interrupt and scheduler ES stop filling the cache once the kernel is drained and keep no closed descriptor after a failed reinitialization

* fix: Hash DRBG: the maximum additional input length is selected by SIZE_MAX, as the kernel macro used before made every seeding fail on 32-bit systems; the builtin ChaCha20 DRNG refuses to generate before it is seeded; SHA-3 accepts an empty update without calling memcpy with NULL; the leancrypto self tests run known answer tests instead of reporting success

* fix: EGD server: a worker reads a bounded amount per round from one connection, so a client streaming entropy insertions no longer holds up every other client of that worker and the shutdown; EGD client: a write to a server that closed the connection no longer raises SIGPIPE in the calling process; getentropy() wrapper: the kernel fallback retries on EINTR and fails with EIO instead of EFAULT

* RPC client: a privileged call interrupted after its request was sent returns -EINPROGRESS instead of -EINTR, as the request may have been applied, and esdm_invoke() does not send it again; fix: an invalid timeout of esdm_rpcc_get_random_bytes_full_timeout() returns -EINVAL instead of aborting; a failing read of an answer is reported as the error it is; the writer-preferring connection lock is used in the real build; RPC server: a connection is idle from its last answer, not its last request

* fix: CUSE: with libfuse >= 3.12 up to 1024 worker threads (-o max_threads) serve the devices instead of libfuse's default of 10, which waiting readers could exhaust and stall every other request including the privileged ioctls; an interrupted privileged ioctl is not run against the kernel again, crediting no entropy twice; a suspend or server exit wakes the pollers of every CUSE daemon (status segment version 4); --pid_namespace without -f no longer kills the daemon at startup; a failing fallback read or write reports its errno instead of EPERM; esdm-proc lets root's writes overtake the unprivileged readers

* fix: Linux kernel addon: the VM fork notifier is registered with CONFIG_VMGENID=m as well, as nixpkgs kernels have it, so cloned VMs no longer keep identical entropy state; the event rings are sized from the OSR, which made module load hit BUG() from OSR 7 on; flake: the testing interfaces are built only on request and the package version is taken from meson.build

* fix: the eBPF unit snippet names CAP_PERFMON and comes after the system call deny list, so bpf and perf_event_open are allowed as intended

* flake: build and test the ESDM on i686; the VM checks verify that the kernel interrupt and scheduler ES deliver credited entropy

* fix: RPC client: the request and unpack buffers are allocated per thread on first use instead of being 129 KiB of static TLS, which made thread creation with small stacks fail or crash in every process linking the client or preloading libesdm_getrandom; random data answers with an impossible return code and seed answers claiming more than they carry are refused with -EPROTO; get_seed asks for no more than the server serves; an oversized privileged request returns -EMSGSIZE; the getrandom interposer survives a fork during its initialization; the status segment has one layout for 32 and 64 bit processes

* fix: RPC server: an unread answer no longer shields a connection from being closed to make room, and a full worker no longer closes connections while other workers have free slots

* fix: EGD server: one prediction resistant generation per connection and round, so a client pipelining PR requests no longer stalls the other clients of its worker; a blocking read is deferred instead of the connection closed while the ESDM is not operational; accepting resumes after a descriptor shortage; GET_PID reports the supervisor under --pid_namespace

* fix: the shipped esdm-server unit hid /proc/sys/crypto/fips_enabled (ProcSubset=pid), silently disabling FIPS mode on a fips=1 kernel; it allows AF_ALG when the Kernel Jitter RNG ES is built; the suspend trigger fires before the system sleeps instead of after resume; esdm-kernel-seeder reseeds at the configured linux-reseed-interval instead of every 10 seconds and stops on SIGTERM while the ESDM is not seeded

* fix: CUSE: a poll with timeout 0 no longer makes the next poll report an event; an interrupted read or write is not served from the kernel device; every daemon thread runs in the isolating network and cgroup namespaces; RNDADDENTROPY checks the caller first and credits at most the buffer's bits, as the kernel does; esdm-proc detaches the mount a crashed instance left behind

* fix: PID namespace supervisor: forwards every signal the daemon handles, loses none arriving at startup, copes with an inherited ignored SIGCHLD and signals no reaped PID; built with clang and LTO, esdm-server and libesdm no longer run separate thread pools and loggers; ESDM_SERVER_FORCE_FIPS is read with secure_getenv()

* fix: NTG.1 seeding from the jitter RNG alone requires the full seed entropy (with SP800-90C oversampling, if enabled) as well; esdm_get_seed() returns -EAGAIN instead of an empty answer when the DRNGs lose their seed during the call; the DRNG instance count no longer overcounts after a failed node allocation

* fix: eBPF ES: the record ending a fetch is no longer dropped, which made the available entropy drift upward; the health tests run in SP800-90C mode as well; the IRQ ES no longer overrides the configured kernel RNG entropy rate; the PKCS#11 status no longer reads a freed token label; es_jent_all_caches takes effect; an es_*_entropy_blocks value that is not a power of two is refused at configure time

* fix: OpenSSL backend: the DRBG self test uses a fixed nonce, as it failed on 32 bit glibc; GnuTLS backend: require GnuTLS >= 3.6.8, whose private DRBG context layout it copies; builtin SHA-2 and SHA-3 count the message length in 64 bits, as SHA-3 lost input after 4 GiB on 32 bit systems

* fix: Linux kernel addon: no printk from the hook path; builds on 32 bit kernels; the kernel patches export their symbols GPL-only in the ESDM namespace, with a DRBG patch for 6.12

* flake: build and test the ESDM on i686 with the OpenSSL backend

* tests: integration test environments detect a missing daemon binary and a server that never came up; fixed sleeps replaced by polling for the seeded state; new regression tests for the fixes above; the EGD raw protocol test also runs under the NTG.1 seeding strategy; the reseed interval test measures the interval instead of sleeping past it and the operational state test retries its scenario; the Jitter RNG only and the initial DRNG security tests also run under the NTG.1 seeding strategy; new tests of the connection limits, the EGD idle timeout and the non-blocking PR request; the node DRNG tests skip where CPU 1 cannot be used; the RPC random bytes tests no longer pass on a failed request; the kernel seeder test requires a clean server exit; a failing worker of the parallel CUSE stress test reports device, size, round and errno

* tests: the security tests (renamed to *_security_test) print their test plan as STEP, REQUIRE, CHECK and RUNUNTIL lines that can be parsed from the JUnit output; a new security test follows the DRNG seed generation through the reseed interval and the request threshold

* fix: TPM2, PKCS#11 and kernel Jitter RNG ES: a failed self test discards the block cache and serves cached blocks without entropy, instead of crediting them in full until the cache is used up

* fix: the prediction resistance DRNG is seeded from entropy collected for the request, bypassing the block caches of the asynchronous entropy sources

* fix: the block cache: a block filled across a reset is never served, and a block is credited at most at the rate configured when it is served, also when the rate changed in the middle of its fill

* fix: the kernel RNG's entropy rate is reduced whenever the interrupt ES kernel add-on is in use, as it takes the interrupts away from the kernel RNG whatever its own rate

* fix: Jitter RNG ES: a collector the library dropped after a failed health test no longer leaves the ES reporting entropy and passing its self test; the self test allocates it anew

* fix: SP800-90B startup test after a health test failure (Linux kernel addon and eBPF ES): the window in which the failure happened no longer counts as one of the passed startup windows

* fix: eBPF ES: the conditioning state is set up before the programs are attached, so raw samples are wiped when the setup fails

* fix: FIPS mode: an unreadable /proc/sys/crypto/fips_enabled counts as FIPS mode, and the decision is kept for the life time of the process

* fix: a non-blocking esdm_get_seed() without enough entropy no longer hands back the content of the caller's buffer

* fix: GnuTLS backend: the conditioning hash runs on a nettle SHA-512 state owned by the ESDM, which is wiped, instead of leaving input in freed GnuTLS memory

* Self tests: the ChaCha20 DRNG test covers the key update after a generate, the leancrypto XDRBG test the condensed additional input and a reseed

* fix: Linux kernel addon: a high resolution timer is detected by sampling it repeatedly, and a coarse timer is not credited; the interrupt ES registration no longer races module unload or the extraction ioctl

* fix: EGD server: when all slots are taken, a new client is served by closing a connection of the UID holding the most connections, and idle connections are closed only for those UIDs - a user with subordinate UIDs can no longer lock everybody else out or have their idle connections closed

* fix: EGD and RPC servers: the socket mode is set when the socket is created instead of by a chmod() of its path afterwards

* fix: RPC server: a worker serves prediction resistant requests for at most 25 ms per round and answers further ones with -EAGAIN, so pipelined requests no longer stall the other clients of the worker

* fix: libesdm_getrandom and CUSE: a non-blocking read no longer waits for the ESDM to be fully seeded again if it lost that state after the check

* fix: CUSE and the aux client trust a status shared memory segment only if it was created by root, the owner of the unprivileged RPC socket or the caller

* fix: esdm-tool wipes the random numbers and seeds it handled; esdm-server removes its PID file with --pid_namespace and empties it otherwise

* fix: EGD and RPC servers: connections are bounded and chosen for closing per user rather than per UID - the subordinate UIDs of /etc/subuid, and those of a user namespace the server can attribute, count as their owner - so a user spreading connections over its subordinate UIDs can neither take all slots nor have the connections of another user, sshd's pre-authentication children among them, closed for its own; root's EGD connections are never closed for a slot

* fix: RPC server: seed requests share the per-round budget of the prediction resistant requests; EGD server: a worker generates prediction resistant bytes for at most 25 ms per round over all its connections, not one generation per connection

* fix: the status reports NTG.1(2024) only when built with the NTG.1 seeding strategy, not whenever the Jitter RNG runs in its NTG.1 mode

* fix: the status shared memory segment is created exclusively, so a segment another user creates in the meantime is never published into

* fix: esdm_get_seed() clears the slot of every entropy source before asking it, so a failing or absent source no longer leaves the caller's bytes in the seed

* fix: TPM2 and kernel Jitter RNG ES: no entropy is claimed while their reads fail

* fix: esdm-server keeps the PID file locked until it is torn down and takes the lock only on the file at the path; libesdm_aux_client trusts a segment of the caller's real UID only when the caller runs unprivileged

* fix: Linux kernel addon: the ring generation is taken before the startup test check, so a health test failure in between is caught; the scheduler ES reports the real registration error; esdm_getrawentropy bounds --samples

* fix: RNDADDTOENTCNT and the EGD command 0xe6 add the credited bits to the auxiliary pool under its lock (esdm_pool_add_entropy()), instead of storing the oversampling-reduced sum of all pools back into the first one, which credited the entropy of the other pools twice, credited again what an extraction took in between and lost 64 bits per call with oversampling; a pool holding no data is credited nothing; an insertion picks the auxiliary pool by the room of its raw count, so a full pool no longer swallows bits while another one has room

* fix: the self tests run before the first seeding of esdm_init() and esdm_reinit(), and no entropy source is credited before its self test passed - an external source failing its self test at start-up fully seeded every DRNG before

* fix: the OpenSSL RAND providers report no maximum request size, so OpenSSL no longer splits a prediction resistant request and serves all but its first 256 bytes from the ordinary DRNG

* fix: EGD server: one status report (0xe4, 0xe5) per connection and round, so a client pipelining them cannot stall a worker; the input buffer is wiped behind every consumed command; EGD client: a wait interrupted by signals keeps its timeout

* fix: DTLS: the OpenSSL backend clears the error queue before each call, so an error the application left behind no longer fails a receive or send and resets the connection; decrypted records are wiped before OpenSSL and GnuTLS free them; esdm_dtls_recv() keeps the parts of a message within the buffer it allocated for it; the Botan backend builds with Botan before 3.13

* fix: external entropy sources: the status never waits for a request in progress, and the status of a provider is fetched at most every 5 seconds; a provider status with NaN, an infinity or invalid UTF-8 is refused; a provider restarted between two status calls is no longer taken for one without STATUS; a provider slow to answer STATUS is not asked again for a minute instead of holding the source for two timeouts and reconnecting without DTLS; the provider server of libesdm_es_ext gives the slot of the client idle longest to a new one when all are taken, and the ESDM reconnects at once to a provider that closed its connection

* fix: PKCS#11 ES: a PIN the token refused is never tried again - every retry consumed one of the token's PIN attempts; TPM2 and PKCS#11 ES recover on the device and module opened before the privilege drop; their status no longer waits for a read in progress; a token label that is not UTF-8 is reported as valid JSON

* fix: Jitter RNG ES: a collector whose reads fail its health tests credits nothing and fails the self test until a read succeeds again or the self test replaces it

* fix: eBPF ES: the sources are disabled with an error where their maps are out of reach after the privilege drop - Linux before 5.19 with kernel.unprivileged_bpf_disabled set - instead of running without their health state and without wiping their samples; a failed insertion into the conditioning pool drops the credit of the events it discarded; the status reads the health state under its lock

* fix: status: the status segment and /proc/esdm/status hold the whole report (16 KiB, segment version 5) and mark a report cut short; esdm_rpcc_status(), esdm_rpcc_status_json() and esdm_rpcc_jent_status() empty the buffer when they fail; the prediction resistance DRNG reports no request figures, which revealed the size and time of the requests of other users; json-c 0.14 or later is required

* fix: esdm_cdev: a write copies the user memory before it takes a connection to the ESDM, and a request waits for a connection at most the timeout, so stalled writers cannot block the readers; RNDADDENTROPY credits once all of its data is in, never more than that data; a state-changing command is never repeated after a signal, so RNDADDTOENTCNT is not credited twice; poll() reports what a read does; the reconnect backoff grows against an ESDM that accepts connections but does not answer; kernel_connect() gets the address in a struct sockaddr_storage

* fix: Linux kernel addon: the kernel's HMAC_DRBG is instantiated with V and C zeroed rather than with uninitialized memory; the testing interface hands out nothing under lockdown, also not the data of a boot test enabled at runtime

* fix: esdm-kernel-seeder credits the kernel again (256 bits per insertion) while the ESDM runs the interrupt ES and linux-reseed-entropy-count is 0

* fix: CUSE: RNDADDTOENTCNT and RNDADDENTROPY fall back to the kernel only for a request that did not reach the ESDM, so nothing is credited twice; an interrupted request fails with EINTR

* fix: esdm-server ignores SIGUSR1 until its suspend handler is installed; esdm-server, the CUSE daemons, esdm-proc and esdm-kernel-seeder log errors and warnings without -v; esdm-tool fails when a status option cannot fetch the status, and prints the status unabridged; a stress worker that cannot allocate its buffer ends instead of hanging its tool

* The documentation describes the jitter RNG NTG.1 shortcut, the errors, signals and wiping of esdm_cdev, the sandboxed EGD client, the DTLS wait of the RPC client, the status of a short buffer, where the init of a source runs, the getrandom shim's __real_*() under --wrap, the IPC resources at shutdown, the eBPF event data, the options of the frontends as they are, the stricter argument checks of RNDADDENTROPY in esdm_cdev, the configuration IOCTL of /dev/esdm_es, and the task wakeup hook and event rings of esdm_es

* Add rpc_bench (meson test --benchmark): the throughput and the CPU time per request of the RPC interface by the calls of its consumers - full, prediction resistant and unseeded reads, getrandom(2) through libesdm_getrandom and, for comparison, the kernel's -, in requests of 32 bytes to 1 MiB, from several threads of several processes

* RPC client: a read larger than one answer carries asks for no more than the server serves from its first request on, rather than learning that by a request refused for its size on every call - a round trip saved per call, one in three for a read of 64 KiB

* DTLS: a message wipes what it took of the record buffers instead of all of them, and the buffer of the records received is not zeroed for every receive - 16 to 33 KiB of memset on either side per message, also for every look at an empty socket

* RPC client: waits for the answer before reading it rather than first finding the socket empty, which took a system call - and on an encrypted connection the receive path of the DTLS - per request

* RPC client: reads the coarse monotonic clock for its own timeouts and the age of a connection, which a clocksource without a vDSO serves without a system call; a deadline of the caller keeps the precise clock

* RPC client: a process holds as many connections as it has calls in flight at the same time, not one per CPU its threads ran on - a call takes the connection its thread had last, or the free one of the lowest number

* RPC client: a call served in several parts - a read beyond 64 KiB, or of prediction resistant data - puts its connection back between them, so that the other threads of the process are not held up for the length of the call

* fix: libesdm_getrandom: getrandom() with GRND_NONBLOCK or GRND_INSECURE waited for as long as requests of other threads held the connections - minutes, with several threads reading prediction resistant data -; it waits 20 ms at most now, and is then answered by the kernel as without an ESDM - a prediction resistant or seed read with GRND_NONBLOCK fails with EAGAIN

* libesdm_getrandom: up to four connections per process (meson option linux-getrandom-num-nodes, which was 1), opened as concurrent requests need them, so the threads of a process are served in parallel

* fix: esdm_cdev: only O_SYNC selects the prediction resistant read, no longer O_DSYNC alone; /proc/esdm/uuid is served by the kernel's RNG while the ESDM cannot serve it, as /dev/esdm_urandom is, instead of being empty; the /proc/esdm snapshots are charged to the memory cgroup of the opener, and their copy in the seq_file buffer is wiped

* fix: esdm_es: ESDM_IRQ_CONF / ESDM_SCHED_CONF refuse an invalid requested entropy before they reset the entropy source; a failing module init tears down only what it set up; the module builds with W=1, against every kernel of the flake with the warnings as errors

* fix: with sp80090c, fips140 or ais2031_drg4, node DRNGs that reach the 2^17 bit cap under sustained load are reseeded by the worker in its next pass, every one of them, with a reseed rather than a new instantiation, and the worker is told each time; reaching the cap no longer clears the state that all DRNGs are seeded, so esdm_get_seed() keeps serving

* fix: esdm_get_random_bytes_full() blocks until the whole request is served instead of returning -EAGAIN or a short count, also while the ESDM is out of operation for a moment; the initial DRNG is reseeded before it is declared spent and no longer takes the ESDM out of operation under load; esdm_get_random_bytes_full_noblock() falls back to the initial DRNG after its reseed instead of answering -EAGAIN

* fix: the prediction resistance DRNG serves its callers in turns, in the order they came, instead of a trylock answering -EAGAIN: one client pipelining prediction resistant reads on one EGD worker no longer starves those of the other workers and of the RPC interface; the EGD server generates one block of 32 bytes per call, so a round of a worker overruns its 25 ms by one seeding at most, and a non-blocking prediction resistant read (0xe0) answers at most 32 bytes

* security: a child of fork() reseeds every DRNG with data unique to it before its first output instead of repeating the random numbers of its parent, see the FORK section of libesdm(3)

* security: esdm-server-signal-helper --resume requests the privileged reseed of all DRNGs (RNDRESEEDCRNG) - the write into the auxiliary pool it made reseeded nothing; the reseed interval counts the time suspended (CLOCK_BOOTTIME)

* fix: esdm_reinit() keeps the data and the entropy of the auxiliary pool, as documented

* fix: RPC server: a request sent as its connection was being closed as idle or to make room is no longer lost - a connection with a request waiting is not idle, and one the server closes itself is shut down for reading first and still answers what its client sent before

* fix: RPC server: a worker accepts up to 512 new connections per round instead of one, so a burst of clients connecting to a busy worker is served in turn with the others instead of being let in one per round while those accepted first went idle and were reaped

* fix: CUSE: O_DSYNC alone selected the prediction resistant read; --username=USER set the user "=USER"

* fix: OpenSSL RNG and SEED-SRC providers, libesdm_getrandom and libesdm_egd_client in TLS mode: with Botan, a process crashed in exit() when its connection was released after the static destructors of the TLS stack, e.g. by OPENSSL_cleanup(); the DTLS and TLS layers no longer call into the TLS stack once the process exits

* fix: RPC client: a prediction resistant answer without data failed the call with -EFAULT; it counts as -EAGAIN now (the blocking call retries, the non-blocking one ends); RPC client and server call the protobuf-c closures through their own type (undefined behaviour, reported by clang's -fsanitize=function)

* fix: esdm-server --pid_namespace: the supervisor could not fork once the daemon ended; esdm_aux_client.h includes <time.h> for struct timespec

* fix: EGD server: what a client sent before the server closed its connection - idle, or to make room for a new one - is taken rather than discarded: a connection with input waiting is not idle, and the server shuts reading down before it closes, so a write that succeeded is never lost and a later one fails

* libesdm_egd_client splits a prediction resistant read into transfers of 224 bytes (ESDM_EGD_MAX_PR_TRANSFER), a multiple of the 32 bytes the prediction resistance DRNG generates per seed, so n bytes cost ceil(n/32) seeds rather than one more per transfer; it needs only libc in builds with es-ext-net but without egd-net TLS, where the EGD tests failed to link

* fix: egd-net: a command has to arrive in full within --io_timeout of its first byte, and in plain mode the first command within --handshake_timeout of the connection - a peer sending a byte at a time no longer holds a probation slot for hours

* fix: egd-net: esdm-egd-net-crl-update checks every CRL of a PEM file and writes nothing if one does not parse; its unit runs as the system user esdm-egd-net-crl (sysusers.d), whose /var/lib/esdm-egd-net-crl the daemons can read - the DynamicUser= state directory below /var/lib/private kept them out

* fix: egd-net: the esdm-egd-net-relay closes upstream connections to a server revoked by reloaded CRLs or whose certificate expired, and with all slots taken serves a new connection at the expense of the least recently used connection of the user holding the most; the esdm-es-ext-relay checks an upstream connection whose handshake spanned a reload of its CRLs

* fix: TLS: a chain has to end in a self-signed trust anchor with GnuTLS as well, so an intermediate CA alone in --ca is refused by every TLS stack; the Botan backend reads the private key into memory that is wiped, and the egd-net units set LimitCORE=0; ExecReload of the units signals with the kill of /bin/sh, so systemctl reload works on NixOS

* fix: External ES socket: every new connection to a provider runs its self test before the provider is credited, so a restarted provider is tested at once; the ESDM status waits at most 500 ms for the STATUS of a provider, which keeps its connection and has its late answer shown when it arrives, and no longer reconnects to a provider; retry, probe and backoff deadlines are kept in nanoseconds rather than whole seconds; a status or name with C1 controls or Unicode bidirectional controls is refused

* fix: esdm-es-pkcs11: only a login the token refuses because of the PIN drops the PIN, other login failures keep it and retry; a token reporting its user PIN on the final try is not logged in to (status pin "final_try"); a PIN given on the command line is not repeated in error messages

* fix: the kernel IRQ add-on loaded after the ESDM started caps the credit of the kernel RNG as well; the interrupt and scheduler sources stay credited while their cache has drained the kernel, so cached blocks are no longer spent uncounted; the per-CPU flush timer of the eBPF sources is pinned to its CPU on Linux 6.7+ and armed anew when lost; the example external entropy source reads its device without blocking, with 1 s per request at most

* fix: esdm-egd-net-server, esdm-egd-net-relay and esdm-es-ext-relay join the threads of their connections before they exit, rather than exit while a thread still runs its end: the RPC client buffers of a connection of the esdm-egd-net-server leaked then, as the exit deleted their thread specific data key under the thread, and a sanitizer build exited with an error

* esdm-server --groupname, the --groupname of esdm-egd-net-relay, esdm-egd-net-server, esdm-es-ext-relay and the provider programs of libesdm_es_ext - esdm-es-pkcs11 among them -, and esdm-vhost-user-rng --group: the group becomes the group of the process after the privilege drop; it and the group of the user are the supplementary groups, so what the daemon may access is unchanged

* tests: sanitizer findings and crashes in daemons the tests start fail the test; the RPC regression tests of tests/fuzz run in every build; each public header is compiled on its own; the test environments wait for daemons to accept connections

* fix: esdm_cdev on Linux 7.3, whose kernel threads look paths up in an empty root of their own: the module connects to the ESDM and reads the kernel's boot_id in the file system context of init again, instead of failing both with -ENOENT and serving every read from the kernel's RNG

* fix: with a jitterentropy before 3.7.0, the RPC call for the status of the Jitter RNG answers with the empty report {} again instead of failing with -ENOENT

* ci: the nix workflow builds esdm_es and esdm_cdev against every kernel of nixpkgs on x86_64 and aarch64, boots the esdm_cdev and eBPF VM tests of each kernel next to the esdm_es one, and runs every other check of the flake; the test CI runs on Ubuntu 26.04 next to 24.04, on x86_64 and arm64, and in containers of Arch Linux, Debian stable, Fedora, openSUSE Tumbleweed, SUSE Linux Enterprise Server 15 SP7 and 16.0 and Red Hat Enterprise Linux 9 and 10, with the OpenSSL of each, the default configuration and the Botan, GnuTLS and leancrypto a distribution packages

* common/ is sorted into subfolders by type - tls/ (the TLS and DTLS layer and the network code), log/, sys/, testmode/, threading/, util/ -, as esdm/ was; the headers keep being included by their names

* RPC server, io_uring event loop: where the kernel has multishot receives into buffer rings (Linux 6.0, liburing 2.4), the ring receives the requests of the connections in the clear and sends their answers with the wait for the next events - about 2 system calls per request instead of 3.6 (the wait and the fork check of the OpenSSL DRBG), 1.2-1.4 us less server CPU per request; connections with DTLS and esdm-server --no_io_uring_multishot keep the poll of the ring

Changes 1.2.3
* Fix handling of non-blocking server response

* Reduce chunk size for the PR IPC interface to 32 bytes for more responsive
server

* CPU ES: Fix RDSEED to RDRAND fallback

* Allow PR DRNG to be used as RBG3(RS) in SP800-90C mode

* Fix SP800-90C instantiate for OpenSSL backend

Changes 1.2.2
* Add TPM 2.0 entropy source

* Reworked threading concept towards multi-connection workers for less memory usage

* Add jitterentropy status RPC call and expose in esdm-tool

* Kernel seeder: add systemd notify support, improve startup speed, double inserted entropy amount

* RPC: set non-blocking sockets, add timeout to non-blocking writes, simplify per-connection buffers, improved performance

* More robust signal handling, overflow checks and argument validation

* RPM SPEC file fixes for openSUSE

* add PPC DARN instruction availability check

* fix crasher in CUSE poller thread

* fix compilation with systemd=disabled

* esdm-server: Fix handling of SIGUSR1 sent by suspend/resume helper (they caused the server to terminate)

* Add backtracking resistance to internal state/output of aux pool

* Automatically add device specific personalization string based on product uuid from DMI, when available

* Assure 256 bit security level on all Intel CPUs

* Fixes for esdm_es and switch to 64 bit timestamps and usage of time deltas

* Support for Linux kernel 6.18 in esdm_es

* Added support for NTG.1 compliant jitterentropy-library 3.7.0

* remove minimally seeded stage

* remove placeholder for atomic DRNG

Changes 1.2.1
* Reduce lock contention and increase throughput (thanks to Markus Theil)

* Add helper tool to externalize the C API to command line (thanks to Markus Theil)

* Update OpenSSL backend (thanks to Markus Theil)

* Update Botan backend (thanks to Markus Theil)

* Update systemd for SLES / Tumbleweed to prevent shutdown hangs

* Establish AIS20/31 DRG.4 compliance (thanks to Markus Theil)

* Place Linux RNG seeder into its own application to avoid chicken-egg problem inside the ESDM (thanks to Markus Theil)

* NTG.1 updates to comply with AIS 20/31 v3.0

* Linux kernel ES: Add cryptographic post-processing with state for esdm_es (SP800-90A DRBG).
  Only use high resolution time code path from now on. All known current CPUs
  support this and allow for storage of fixed with timestamps. Timestamps
  are now stored per CPU and directly take part in a combined seed of multiple
  per-CPU buffers via a scather gather list. Clear state when suspending or
  rebooting.

* Don't expose testing interface of esdm_es when in lockdown mode.

* Add NIST test vectors for Botan HMAC-DRBG(SHA-512).

* Fix: RDRAND feature detection.

* Fix: performance with many worker threads on many core systems.

* Added improved systemd support (notify, socket activation). Switch default
  path to /run in order to prevent systemd deprecation notices. Small refactoring
  of systemd service generation to unify socket and non-socket activation paths.

* Fix: FIPS 140 init works now, added checksum generation to esdm-tool for better
  scripting.

* Add explicit OSR to esdm_es. Expose different ES' via Makefile options.

Changes 1.2.0
* fix: to prevent a DoS against the RPC channel, limit the slow operations of esdm_get_random_bytes_pr and esdm_get_seed to allow only one call in flight. If another call comes in while one process is ongoing, return -EAGAIN to free the RPC channel.

* fix: handle rogue libesdm-aux clients more gracefully - if a client received a notification to supply entropy, but it fails to send anything, the ESDM will not send a notification again. This issue is alleviated by checking the need_entropy common variable

* switch from CLOCK_REALTIME to CLOCK_MONOTONIC for wait operations

* add esdm.spec file for generating an RPM

Changes 1.1.1:
* fix: properly use the mutex absolute time argument, timedlock handling and mutex destruction in the ESDM RPC client lib

* fix: race condition in worker thread execution

Changes 1.1.0:
* fix: name of leancrypto DRNG

* fix: getentropy returns 0 on success

* enhancement: only establish connection to server once and when needed

* fix: SHM in CUSE must be attached RD/WR

* enhancement: add esdm_aux_client library

Changes 1.0.2:
* hardening: enable -fzero-call-used-regs=used-gpr

* editorial: rename logging* symbols to esdm_logging* - this is purely internal, but considering some of these symbols are externally visible, libesdm_rpc_client pollutes the namespace of consumers

* enhancement: significant performance increase of RPC communication

* fix: Poll writer woke up as status variable was not properly initialized

* fix: proper shut down sequence of ESDM daemons

Changes 1.0.1:
* enhancement/fix: add support for multiple ESDM RPC client connection initializations

* fix: If a process select/poll on a CUSE file, the system now goes properly to sleep

* fix: If there is high load on the CUSE daemons - make sure they properly shut down on reboot

Changes 1.0.0:
* fix (re)initialization of ESDM to set correct entropy level

* IRQ/Sched ES: add support to retry accessing the kernel with -i and -s flags

* enhancement: Jitter RNG ES generates data asynchronously

* enhancement: add kernel Jitter RNG ES

* enhancement: add leancrypto, OpenSSL and Botan crypto provider backends

* enhancement: add OpenSSL, Botan seed provider (leancrypto ESDM seed provider is found in leancrypto source code)

* fix: ESDM server - systemd unit executes server in current mount namespace

* editorial: apply clang-format

* fix: CUSE daemons may hang during shutdown due to busy mounts

* fix: resynchronize CUSE daemons and ESDM server upon ESDM server restart

* enhancement: ESDM server status splits up FIPS 140 and SP800-90C compliance

* rename compile time option "oversample_es" to "sp80090c" which is now disabled
  by default considering that with its enabling, the oversampling is applied
  unconditionally during startup

Changes 0.6.0:
* Move ESDM apps into separate namespaces to limit their privilege even further (e.g. no possibility to create network connections)

* Add German AIS 20/31 (draft 2022) NTG.1 compliance support

* the blocking property of an interface is implemented in the client - the
  server reports -EAGAIN for a blocking behavior

* add "emergency seeding" when entropy sources cannot collectively deliver
  256 bits of entropy, pull data repeatedly until 256 bits are received

* export esdm_rpc_client.h with all depending header files to allow external
  clients to be developed

* update IRQ/Scheduler ES health test to match LRNG

* bug fix: correctly calculate memory offsets

* enhancement: Sched/IRQ ES code in ESDM can handle if kernel-parts have
  different data structure size for sending entropy to user space

* IRQ/Sched ES: Switch to /dev/esdm_es character devices a user space interfaces

Changes 0.5.0:
* Linux kernel entropy feeder is now always enabled

* Add Linux /dev/hwrng entropy source

* FIPS IG 7.19/D.K / BSI NTG.1: use a new DRNG instance executed with PR

* Handle communication errors between client and server gracefully

* ES monitor now runs for lifetime of the ESDM

* add interface to access entropy sources - esdm_get_seed including making it accessible via getrandom(2)

* fix of deadlocks during shutdown

Changes 0.4.0:
* Start CUSE daemons independently from ESDM server

* add support for invoking DRNG with prediction resistance when opening
  /dev/random with O_SYNC or using the esdm_get_random_bytes_pr API.
  This reestablishes the NTG.1 property as well as well as supports
  using the DRBG as a conditioning component pursuent to SP800-90C and
  FIPS 140 IG 7.19 / D.K.

* initialize the DRNG immediately with 256 bits (disregarding 32/128 bits)

* add interrupt entropy source

* modify collection in scheduler ES: maintain a hash state per CPU as a per-CPU entropy pool

* add proper interrupt/signal handling code to the ESDM RPC client library

* privilege level change in CUSE is now limited to caller only

* add support to allow ld.so.preload to be used to refer to libesdm-getrandom.so for a system-wide replacement of getrandom/getentropy system call.

Changes 0.3.0:
* Replace protobuf-c-rpc with built-in RPC mechanism reducing amount of mallocs,
  performing proper zeroization and being fully thread-aware

* Testing: disable /dev/random fallbacks for verifying RPC operation

* RNDGETENTCNT returns the seed state of the auxiliary entropy pool only. This
  makes it 100% ABI compliant to random.c

* Add ChaCha20 DRNG to regular code base

* Add SHA-3 conditioning hash to regular code base

* Add /proc/sys/kernel/random files handler along with SELinux policy, tested
  with:
	- rng-tools
	- jitterentropy-rngd
	- haveged

Changes 0.2.0:
* Initial public version
