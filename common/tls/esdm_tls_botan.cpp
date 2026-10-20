/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * (D)TLS of esdm_tls_backend.h by Botan, for crypto_backend=botan: TLS 1.3 on
 * a stream socket, with the files, the verification and the revocation policy
 * of Esdm_Tls_Credentials and esdm_tls_botan_verify(), and the DTLS 1.2 with
 * the pre-shared key of the local DTLS on SOCK_SEQPACKET - one policy, one set
 * of callbacks and one connection for both, see Esdm_Tls_Policy.
 *
 * A Botan TLS channel does no I/O of its own: what it has to send it hands to
 * tls_emit_data(), which is collected here and pushed to the socket by
 * Esdm_Tls_Callbacks::flush() as far as the socket takes it - the rest waits
 * for the socket to become writable, see esdm_tls_backend_flush(). On
 * SOCK_SEQPACKET, what one call hands over - a record, or a flight of them -
 * goes out as one message of the socket. What the socket has is fed to the
 * channel with received_data() - one message of the socket per call on
 * SOCK_SEQPACKET -, and the application data of a record comes back through
 * tls_record_received(), which collects it here until esdm_tls_backend_recv()
 * hands it out: as a stream on a stream socket, record by record on
 * SOCK_SEQPACKET.
 *
 * The certificate chain of the peer is verified by esdm_tls_botan_verify(),
 * which esdm_tls_backend_ctx_files() installs, rather than by Botan's default:
 * that one checks the server name the client indicates, which an address
 * literal is not - see esdm_tls_botan_name_matches() - and does not hand out
 * the path it verified, which the revocation policy of esdm_tls.c is run on
 * right there. A connection of a context without the files - the local DTLS,
 * whose suites know no certificate - refuses every chain.
 *
 * TLS 1.3 takes the algorithms of BSI TR-02102-2 alone, the hybrid key
 * exchange of ML-KEM Botan has ahead of the conventional one, see
 * Esdm_Tls_Policy and "Algorithms" in esdm_tls.h. A certificate whose key no
 * signature scheme of the policy signs with is refused by the context, see
 * esdm_tls_botan_signs().
 *
 * No exception crosses into the C code: every entry point catches them and
 * reports an errno.
 */

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/secmem.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/tls_signature_scheme.h>
#include <botan/version.h>
#include <botan/x509_crl.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
#include <botan/ipv6_address.h>
#endif

#include "esdm_logger.h"
#include "esdm_tls.h"
#include "esdm_tls_backend.h"
#include "memset_secure.h"

namespace
{

/*
 * The groups of TLS 1.3 of esdm_tls.h in its order, as far as Botan has them,
 * by their codes of TLS: the hybrid of ML-KEM SecP384r1MLKEM1024 - with Botan
 * 3.8 and later, built with the modules ml_kem and tls_13_pqc; not the hybrids
 * with X25519 and P-256, of 128 bits, nor ML-KEM alone -, then the curves
 * secp384r1, secp256r1, secp521r1 and those of Brainpool, then the finite
 * field groups of 3072 and 4096 bits
 */
static const uint16_t esdm_tls_botan_groups[] = {
	0x11ED, 24, 23, 25, 32, 31, 33, 257, 258,
};

/* The hybrid of ML-KEM, if Botan has it */
static std::optional<Botan::TLS::Group_Params> esdm_tls_botan_hybrid()
{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 8, 0)
	Botan::TLS::Group_Params group(esdm_tls_botan_groups[0]);

	if (group.is_pqc_hybrid() && group.is_available())
		return group;
#endif
	return std::nullopt;
}

/*
 * The protocol of a transport, and the secure minimal mode of
 * esdm_tls_backend.h on both - a connection lives as long as it does, with the
 * one full handshake it started with:
 *
 *  - Nothing is resumed: the session manager of the contexts keeps no session
 *    (Session_Manager_Noop) and issues no ticket of TLS 1.2, and a server of
 *    TLS 1.3 issues none either. A client offers no session and no pre-shared
 *    key of resumption, as it has none - but a client of DTLS 1.2 sends an
 *    empty session_ticket extension all the same, and a server of DTLS 1.2 a
 *    session ID, which Botan gives no way to leave out.
 *  - No early data (0-RTT): Botan has none.
 *  - No renegotiation either way: a request for one ends the connection, and
 *    no resumption stands in for one. Botan has no post-handshake
 *    authentication of TLS 1.3, no compression and no heartbeat.
 *  - DTLS 1.2 requires the extended master secret and, for CBC,
 *    Encrypt-then-MAC - see Esdm_Tls_Callbacks::tls_session_established(),
 *    which checks both whatever the version of Botan.
 *
 * On a stream socket, TLS 1.3 exactly, with the groups of ML-KEM first and a
 * server that requires a certificate.
 *
 * On SOCK_SEQPACKET, the local DTLS: DTLS 1.2 exactly, ECDHE with the
 * pre-shared key - preferably TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 of
 * RFC 8442 on brainpoolP512r1; TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 with
 * Encrypt-then-MAC, and secp521r1, with a peer that has neither - the OpenSSL
 * and GnuTLS backends. The link MTU of esdm_tls_backend.h, as nothing is
 * fragmented on the connection.
 */
class Esdm_Tls_Policy final : public Botan::TLS::Policy {
    public:
	Esdm_Tls_Policy(bool server, bool dgram)
		: m_server(server), m_dgram(dgram)
	{
	}

	/* TLS 1.3: AES-GCM, not ChaCha20-Poly1305 - see esdm_tls.h */
	std::vector<std::string> allowed_ciphers() const override
	{
		if (m_dgram)
			return { "AES-256/GCM", "AES-256" };
		return { "AES-256/GCM", "AES-128/GCM" };
	}

	std::vector<std::string> allowed_macs() const override
	{
		if (m_dgram)
			return { "AEAD", "SHA-384" };
		return Botan::TLS::Policy::allowed_macs();
	}

	/*
	 * The suites of the local DTLS, GCM first. Botan's own list leaves the
	 * CBC suites out of DTLS: its MAC-then-encrypt decryption keeps a timing
	 * channel of Lucky Thirteen, which DTLS lets an attacker observe as often
	 * as it likes. With Encrypt-then-MAC, the MAC is checked over the
	 * ciphertext before anything is decrypted, and there is no such channel:
	 * the CBC suite is taken with it only - see tls_session_established().
	 * A suite this build of Botan does not have is left out.
	 */
	std::vector<uint16_t>
	ciphersuite_list(Botan::TLS::Protocol_Version version) const override
	{
		/* ECDHE_PSK_WITH_AES_256_GCM_SHA384, ..._256_CBC_SHA384 */
		static const uint16_t suites[] = { 0xD002, 0xC038 };
		std::vector<uint16_t> list;

		if (!m_dgram)
			return Botan::TLS::Policy::ciphersuite_list(version);

		for (const auto id : suites) {
			const auto suite = Botan::TLS::Ciphersuite::by_id(id);

			if (suite && suite->valid())
				list.push_back(id);
		}
		return list;
	}

	bool negotiate_encrypt_then_mac() const override
	{
		return true;
	}

	std::vector<std::string> allowed_key_exchange_methods() const override
	{
		if (m_dgram)
			return { "ECDHE_PSK" };
		return Botan::TLS::Policy::allowed_key_exchange_methods();
	}

	/*
	 * A PSK suite signs nothing: the key exchange authenticates it. TLS 1.3
	 * signs with ECDSA and RSA-PSS - not EdDSA, and Botan has no signature
	 * scheme of ML-DSA.
	 */
	std::vector<std::string> allowed_signature_methods() const override
	{
		if (m_dgram)
			return { "IMPLICIT" };
		return { "ECDSA", "RSA" };
	}

	/*
	 * TLS 1.3: the groups of esdm_tls_botan_groups Botan has. A server of
	 * Botan takes the hybrid if the client offers a key share of it, else
	 * the first group the client lists, by a HelloRetryRequest: two sides of
	 * this policy agree on the first one.
	 */
	std::vector<Botan::TLS::Group_Params>
	key_exchange_groups() const override
	{
		std::vector<Botan::TLS::Group_Params> groups;

		if (m_dgram)
			return { Botan::TLS::Group_Params::BRAINPOOL512R1,
				 Botan::TLS::Group_Params::SECP521R1 };

		for (const auto code : esdm_tls_botan_groups) {
			Botan::TLS::Group_Params group(code);

			if (group.is_available())
				groups.push_back(group);
		}
		return groups;
	}

	/*
	 * TLS 1.3: key shares of the hybrid, and of the first curve for a server
	 * without it - Botan's default sends the latter only, which costs a
	 * HelloRetryRequest with every server preferring the hybrid
	 */
	std::vector<Botan::TLS::Group_Params>
	key_exchange_groups_to_offer() const override
	{
		std::vector<Botan::TLS::Group_Params> offer;
		const auto hybrid = esdm_tls_botan_hybrid();

		if (m_dgram)
			return Botan::TLS::Policy::key_exchange_groups_to_offer();

		if (hybrid)
			offer.push_back(*hybrid);
		for (const auto &group : key_exchange_groups()) {
			if (group.is_pure_ecc_group()) {
				offer.push_back(group);
				break;
			}
		}
		return offer;
	}

	/*
	 * The security level of BSI TR-02102 for the certificates and the key
	 * exchange: RSA and finite field groups of 3072 bits and more, elliptic
	 * curves of 256 bits and more, signatures of 128 bits of security
	 */
	size_t minimum_rsa_bits() const override
	{
		return 3072;
	}

	size_t minimum_dh_group_size() const override
	{
		return 3072;
	}

	size_t minimum_ecdh_group_size() const override
	{
		return 256;
	}

	size_t minimum_ecdsa_group_size() const override
	{
		return 256;
	}

	size_t minimum_signature_strength() const override
	{
		return 128;
	}

	bool allow_tls12() const override
	{
		return false;
	}

	bool allow_tls13() const override
	{
		return !m_dgram;
	}

	bool allow_dtls12() const override
	{
		return m_dgram;
	}

	bool require_client_certificate_authentication() const override
	{
		return m_server && !m_dgram;
	}

	/* The minimal mode, see above */
	bool allow_client_initiated_renegotiation() const override
	{
		return false;
	}

	bool allow_server_initiated_renegotiation() const override
	{
		return false;
	}

	bool allow_insecure_renegotiation() const override
	{
		return false;
	}

	bool abort_connection_on_undesired_renegotiation() const override
	{
		return true;
	}

	bool allow_resumption_for_renegotiation() const override
	{
		return false;
	}

	size_t new_session_tickets_upon_handshake_success() const override
	{
		return 0;
	}

	bool reuse_session_tickets() const override
	{
		return false;
	}

	bool allow_dtls_epoch0_restart() const override
	{
		return false;
	}

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
	bool require_extended_master_secret() const override
	{
		return true;
	}
#endif

	size_t dtls_default_mtu() const override
	{
		return ESDM_DTLS_LINK_MTU;
	}

	/*
	 * The cookie exchange protects a server against spoofed addresses -
	 * a client making it send a flight to somebody else. A connected Unix
	 * domain socket has no address to spoof. Botan requires it from 3.13
	 * on; before, the empty Credentials_Manager::dtls_cookie_secret() of
	 * Esdm_Tls_Psk_Credentials turns it off.
	 */
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
	bool dtls_server_require_cookie_exchange() const override
	{
		return false;
	}
#endif

    private:
	bool m_server;
	bool m_dgram;
};

#ifdef ESDM_DTLS
/*
 * The pre-shared key of the local DTLS of either side and its identity, see
 * esdm_tls_backend.h; no certificate. A server knows no other identity, and
 * refuses a client with another one.
 */
class Esdm_Tls_Psk_Credentials final : public Botan::Credentials_Manager {
    public:
	std::string psk_identity(const std::string &type,
				 const std::string &context,
				 const std::string &identity_hint) override
	{
		(void)type;
		(void)context;
		(void)identity_hint;

		return ESDM_DTLS_PSK_IDENTITY;
	}

	/*
	 * Where psk() of TLS 1.2 looks the key up. psk() stays Botan's: it
	 * asks the empty dtls_cookie_secret() for the secret of the DTLS
	 * cookies, see Esdm_Tls_Policy. A PSK of TLS 1.2 has no PRF of its
	 * own.
	 */
	std::vector<Botan::TLS::ExternalPSK>
	find_preshared_keys(std::string_view host,
			    Botan::TLS::Connection_Side whoami,
			    const std::vector<std::string> &identities,
			    const std::optional<std::string> &prf) override
	{
		std::vector<Botan::TLS::ExternalPSK> psks;

		(void)host;
		(void)whoami;
		(void)prf;

		if (!identities.empty() &&
		    std::find(identities.begin(), identities.end(),
			      ESDM_DTLS_PSK_IDENTITY) == identities.end())
			return psks;

		psks.emplace_back(
			ESDM_DTLS_PSK_IDENTITY, "SHA-384",
			Botan::secure_vector<uint8_t>(
				esdm_dtls_psk,
				esdm_dtls_psk + sizeof(esdm_dtls_psk)));
		return psks;
	}
};
#endif /* ESDM_DTLS */

class Esdm_Tls_Callbacks;
class Esdm_Tls_Credentials;

/*
 * The verification of the chain of the peer, installed by
 * esdm_tls_backend_ctx_files(): esdm_tls_botan_verify()
 */
typedef void (*esdm_tls_botan_verify_fn)(
	Esdm_Tls_Callbacks &cb,
	const std::vector<Botan::X509_Certificate> &cert_chain,
	const std::vector<std::optional<Botan::OCSP::Response> > &ocsp_responses,
	const std::vector<Botan::Certificate_Store *> &trusted_roots,
	Botan::Usage_Type usage, const Botan::TLS::Policy &policy);

struct Esdm_Tls_Ctx {
	bool server;
	/* SOCK_SEQPACKET: the local DTLS */
	bool dgram;
	std::shared_ptr<Botan::RandomNumberGenerator> rng;
	std::shared_ptr<Botan::Credentials_Manager> creds;
	std::shared_ptr<const Esdm_Tls_Policy> policy;
	std::shared_ptr<Botan::TLS::Session_Manager_Noop> sessions;
	/* The files, and their verification: esdm_tls_backend_ctx_files() */
	std::shared_ptr<Esdm_Tls_Credentials> files;
	esdm_tls_botan_verify_fn verify = nullptr;
};

/* An alert that is about a certificate: refused, or not presented */
static bool esdm_tls_botan_cert_alert(Botan::TLS::Alert::Type type)
{
	switch (type) {
	case Botan::TLS::Alert::BadCertificate:
	case Botan::TLS::Alert::UnsupportedCertificate:
	case Botan::TLS::Alert::CertificateRevoked:
	case Botan::TLS::Alert::CertificateExpired:
	case Botan::TLS::Alert::CertificateUnknown:
	case Botan::TLS::Alert::UnknownCA:
	case Botan::TLS::Alert::AccessDenied:
	case Botan::TLS::Alert::CertificateRequired:
		return true;
	default:
		return false;
	}
}

/* The connection as the channel sees it */
class Esdm_Tls_Callbacks final : public Botan::TLS::Callbacks {
    public:
	Esdm_Tls_Callbacks(int fd, bool dgram, bool server,
			   const char *server_name,
			   esdm_tls_backend_check check, void *check_arg,
			   esdm_tls_botan_verify_fn verify)
		: m_fd(fd), m_dgram(dgram), m_server(server),
		  m_server_name(server_name ? server_name : ""), m_check(check),
		  m_check_arg(check_arg), m_verify(verify)
	{
	}

	/* What was received and not handed out is plaintext */
	~Esdm_Tls_Callbacks() override
	{
		memset_secure(m_in.data(), 0, m_in.size());
		memset_secure(m_out.data(), 0, m_out.size());
		for (auto &rec : m_records)
			memset_secure(rec.data(), 0, rec.size());
	}

	/* On SOCK_SEQPACKET, a message of its own */
	void tls_emit_data(std::span<const uint8_t> data) override
	{
		if (m_dgram)
			m_msgs.emplace_back(data.begin(), data.end());
		else
			m_out.insert(m_out.end(), data.begin(), data.end());
	}

	/*
	 * On SOCK_SEQPACKET, a record of its own - none of the empty ones, which
	 * carry nothing, not even the byte of esdm_dtls.c in front
	 */
	void tls_record_received(uint64_t seq_no,
				 std::span<const uint8_t> data) override
	{
		(void)seq_no;
		if (m_dgram) {
			if (!data.empty())
				m_records.emplace_back(data.begin(),
						       data.end());
		} else {
			m_in.insert(m_in.end(), data.begin(), data.end());
		}
	}

	void tls_alert(Botan::TLS::Alert alert) override
	{
		if (alert.type() == Botan::TLS::Alert::CloseNotify) {
			m_peer_closed = true;
		} else if (alert.is_fatal()) {
			m_fatal = true;
			m_alert = alert.type();
			m_error = "alert received: " + alert.type_string();
		}
	}

	/*
	 * The minimal mode, see Esdm_Tls_Policy: a resumed session is refused,
	 * and so is one of DTLS 1.2 without the extended master secret (RFC
	 * 7627), which binds the master secret to the handshake it came from,
	 * and a CBC suite without Encrypt-then-MAC, see
	 * Esdm_Tls_Policy::ciphersuite_list(): the exception ends the handshake
	 * with a fatal alert. Every peer of the ESDM offers and agrees to both,
	 * whichever its TLS stack - and TLS 1.3 has the one built in and no CBC
	 * suite.
	 */
	void tls_session_established(
		const Botan::TLS::Session_Summary &session) override
	{
		if (session.was_resumption())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::InsufficientSecurity,
				"a resumed session");
		if (session.version().is_pre_tls_13() &&
		    !session.supports_extended_master_secret())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::InsufficientSecurity,
				"no extended master secret");
		if (session.ciphersuite().cbc_ciphersuite() &&
		    !session.supports_encrypt_then_mac())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::InsufficientSecurity,
				"CBC without Encrypt-then-MAC");

		m_cipher = session.ciphersuite().to_string();
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 7, 0)
		/* The group, which a summary tells from 3.7 on */
		m_group = session.kex_parameters().value_or("");
#endif
	}

	/* A context without the files takes no certificate */
	void tls_verify_cert_chain(
		const std::vector<Botan::X509_Certificate> &cert_chain,
		const std::vector<std::optional<Botan::OCSP::Response> >
			&ocsp_responses,
		const std::vector<Botan::Certificate_Store *> &trusted_roots,
		Botan::Usage_Type usage, std::string_view hostname,
		const Botan::TLS::Policy &policy) override
	{
		(void)hostname;

		if (!m_verify || !m_check) {
			m_error =
				"certificate verify failed: no certificate is taken";
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::BadCertificate, m_error);
		}
		m_verify(*this, cert_chain, ocsp_responses, trusted_roots,
			 usage, policy);
	}

	/*
	 * Push out what the channel emitted, as far as the socket takes it - on
	 * SOCK_SEQPACKET each message whole. Throws nothing.
	 *
	 * @return 0 when all is out, -EAGAIN if not, a negative errno
	 */
	int flush() noexcept
	{
		while (!m_msgs.empty()) {
			const auto &msg = m_msgs.front();
			int ret = send_part(msg.data(), msg.size());

			if (ret < 0)
				return ret;
			if (static_cast<size_t>(ret) != msg.size()) {
				set_error("a record cut by the socket");
				return -EIO;
			}
			m_msgs.pop_front();
		}

		while (m_out_off < m_out.size()) {
			int ret = send_part(m_out.data() + m_out_off,
					    m_out.size() - m_out_off);

			if (ret < 0)
				return ret;
			m_out_off += static_cast<size_t>(ret);
		}

		memset_secure(m_out.data(), 0, m_out.size());
		m_out.clear();
		m_out_off = 0;
		return 0;
	}

	bool out_pending() const
	{
		return !m_msgs.empty() || m_out_off < m_out.size();
	}

	/* Is application data there to be handed out? */
	bool has_data() const
	{
		return m_dgram ? !m_records.empty() : m_in_off < m_in.size();
	}

	/* m_error, where an exception must not escape */
	void set_error(const char *text) noexcept
	{
		try {
			m_error = text;
		} catch (...) {
		}
	}

	int m_fd;
	bool m_dgram;
	bool m_server;
	std::string m_server_name;
	esdm_tls_backend_check m_check;
	void *m_check_arg;
	esdm_tls_botan_verify_fn m_verify;

	/* Stream socket: what is to be sent, and what was received */
	std::vector<uint8_t> m_out;
	size_t m_out_off = 0;
	std::vector<uint8_t> m_in;
	size_t m_in_off = 0;

	/* SOCK_SEQPACKET: the messages to be sent, and the records received */
	std::deque<std::vector<uint8_t> > m_msgs;
	std::deque<std::vector<uint8_t> > m_records;

	bool m_peer_closed = false;
	bool m_eof = false;
	/*
	 * The channel is dead: a fatal alert of the peer, or one it sent for
	 * what it got - m_alert tells which
	 */
	bool m_fatal = false;
	Botan::TLS::Alert::Type m_alert = Botan::TLS::Alert::CloseNotify;
	std::string m_cipher = "unknown";
	/* The key exchange group, empty while unknown */
	std::string m_group;
	std::string m_error;

    private:
	/* @return the bytes the socket took, -EAGAIN, a negative errno */
	int send_part(const uint8_t *buf, size_t len) noexcept
	{
		for (;;) {
			ssize_t n = send(m_fd, buf, len,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (n >= 0)
				return n > INT32_MAX ? INT32_MAX :
						       static_cast<int>(n);
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return -EAGAIN;
			if (errno == ECONNRESET || errno == EPIPE ||
			    errno == ENOTCONN) {
				set_error("connection closed by the peer");
				return -ECONNRESET;
			}
			set_error(std::strerror(errno));
			return -EIO;
		}
	}
};

struct Esdm_Tls_Conn {
	std::shared_ptr<Esdm_Tls_Callbacks> callbacks;
	std::unique_ptr<Botan::TLS::Channel> channel;
};

/* A fatal alert of the peer, or one that ended the channel here */
static int esdm_tls_botan_alert_error(Esdm_Tls_Conn *c)
{
	return esdm_tls_botan_cert_alert(c->callbacks->m_alert) ? -EACCES :
								  -EPROTO;
}

/*
 * The channel took what it was fed: the exception it threw, if any, is the
 * end of the connection, see esdm_tls_botan_feed().
 *
 * @return 0, or a negative errno
 */
static int esdm_tls_botan_received(Esdm_Tls_Conn *c, const uint8_t *buf,
				   size_t len)
{
	auto &cb = *c->callbacks;

	/*
	 * The channel sends the alert of what it throws, and is dead then -
	 * for good: every later call fails the same way.
	 */
	try {
		c->channel->received_data(std::span<const uint8_t>(buf, len));
	} catch (const Botan::TLS::TLS_Exception &e) {
		if (cb.m_error.empty())
			cb.m_error = e.what();
		cb.m_fatal = true;
		cb.m_alert = e.type();
		return esdm_tls_botan_alert_error(c);
	} catch (const std::bad_alloc &) {
		cb.m_fatal = true;
		cb.m_alert = Botan::TLS::Alert::InternalError;
		cb.set_error("out of memory");
		return -ENOMEM;
	} catch (const std::exception &e) {
		cb.m_fatal = true;
		cb.m_alert = Botan::TLS::Alert::DecodeError;
		if (cb.m_error.empty())
			cb.set_error(e.what());
		return -EPROTO;
	}

	if (cb.m_fatal)
		return esdm_tls_botan_alert_error(c);
	return 0;
}

/*
 * Feed the channel what the socket has - one message per call of
 * received_data() on SOCK_SEQPACKET -, until the socket has nothing more or
 * the channel has application data.
 *
 * @return 0 if the socket is drained or data is there, -EAGAIN if nothing was
 *	   there to be read, -ECONNRESET at the end of the connection, -EACCES
 *	   or -EPROTO if the channel refused what it got, another negative errno
 */
static int esdm_tls_botan_feed(Esdm_Tls_Conn *c)
{
	auto &cb = *c->callbacks;
	/*
	 * On the heap: a client may run on a thread with a small stack. And
	 * left uninitialized: it receives the records as they are on the wire,
	 * which are of no secrecy, so there is nothing to wipe afterwards
	 * either. Zeroing 17 KiB for every call, also for one that finds the
	 * socket empty, was a share of every request.
	 */
	const size_t buflen = ESDM_DTLS_LINK_MTU + 512;
	std::unique_ptr<uint8_t[]> buf(new uint8_t[buflen]);
	bool got = false;
	int ret = 0;

	while (!cb.has_data() && !cb.m_peer_closed) {
		ssize_t n = recv(cb.m_fd, buf.get(), buflen, MSG_DONTWAIT);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = got ? 0 : -EAGAIN;
				break;
			}
			cb.m_error = std::strerror(errno);
			ret = (errno == ECONNRESET || errno == ENOTCONN) ?
				      -ECONNRESET :
				      -EIO;
			break;
		}
		if (n == 0) {
			cb.m_eof = true;
			if (cb.m_error.empty())
				cb.m_error =
					"connection closed by the peer without a closing alert";
			ret = -ECONNRESET;
			break;
		}

		got = true;
		ret = esdm_tls_botan_received(c, buf.get(),
					      static_cast<size_t>(n));
		if (ret)
			break;
	}

	/* Whatever the channel answered - alerts included - goes out */
	if (cb.flush() == -ECONNRESET && !ret)
		ret = -ECONNRESET;

	return ret;
}

#ifdef ESDM_TLS_AUTH

/******************************************************************************
 * The certificates
 ******************************************************************************/

/* The PEM blocks of @text labeled @label, each with its markers */
static std::vector<std::string> esdm_tls_botan_pem_blocks(const std::string &text,
							  const std::string &label)
{
	const std::string begin = "-----BEGIN " + label + "-----";
	const std::string end = "-----END " + label + "-----";
	std::vector<std::string> blocks;
	size_t pos = 0;

	for (;;) {
		size_t b = text.find(begin, pos), e;

		if (b == std::string::npos)
			break;
		e = text.find(end, b);
		if (e == std::string::npos)
			throw Botan::Decoding_Error("PEM block of " + label +
						    " without its end");
		e += end.size();
		blocks.emplace_back(text.substr(b, e - b));
		pos = e;
	}

	return blocks;
}

static std::string esdm_tls_botan_read(const std::string &path)
{
	std::ifstream in(path, std::ios::binary);
	std::ostringstream text;

	if (!in)
		throw Botan::Stream_IO_Error("cannot open " + path);
	text << in.rdbuf();

	return text.str();
}

/* Largest key file read - a PKCS#8 key of RSA 16384 is less than 13 KiB */
#define ESDM_TLS_BOTAN_MAX_KEY_FILE (64 * 1024)

/*
 * The contents of the private key file @path, in memory that is wiped when it
 * is freed - also on the way out of an exception: read(2) straight into a
 * secure_vector. A stream, as esdm_tls_botan_read() reads the public files
 * with, holds what it read in buffers of its own, which nothing wipes.
 */
static Botan::secure_vector<uint8_t>
esdm_tls_botan_read_secret(const std::string &path)
{
	Botan::secure_vector<uint8_t> buf(ESDM_TLS_BOTAN_MAX_KEY_FILE + 1);
	size_t len = 0;
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		throw Botan::Stream_IO_Error("cannot open " + path);

	while (len < buf.size()) {
		ssize_t n = read(fd, buf.data() + len, buf.size() - len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			int errsv = errno;

			close(fd);
			throw Botan::Stream_IO_Error("cannot read " + path +
						     ": " +
						     std::strerror(errsv));
		}
		if (!n)
			break;
		len += static_cast<size_t>(n);
	}
	close(fd);

	if (len > ESDM_TLS_BOTAN_MAX_KEY_FILE)
		throw Botan::Decoding_Error("the key file " + path +
					    " is too large");
	/* Shrinks in place: what is cut off is zero or wiped already */
	buf.resize(len);

	return buf;
}

static std::vector<Botan::X509_Certificate>
esdm_tls_botan_load_certs(const std::string &path)
{
	std::vector<Botan::X509_Certificate> certs;

	for (const auto &block : esdm_tls_botan_pem_blocks(
		     esdm_tls_botan_read(path), "CERTIFICATE")) {
		Botan::DataSource_Memory src(block);

		certs.emplace_back(src);
	}
	if (certs.empty())
		throw Botan::Decoding_Error("no certificate in " + path);

	return certs;
}

/*
 * Does a signature scheme of @policy sign with a key of the algorithm @algo?
 * Botan chooses the certificate of a side by the algorithms of the signature
 * schemes its peer offers, and signs the handshake with the first scheme of
 * the policy for the key the peer offers as well: a certificate on a key no
 * scheme of the policy is for makes every handshake fail for want of a
 * certificate. One on ML-DSA is such, as Botan has no signature scheme of TLS
 * for it (3.13).
 */
static bool esdm_tls_botan_signs(const Botan::TLS::Policy &policy,
				 const std::string &algo)
{
	for (const auto &scheme : policy.allowed_signature_schemes()) {
		if (scheme.is_available() && scheme.algorithm_name() == algo)
			return true;
	}
	return false;
}

/* The own certificate and key, and the trust anchors and CRLs */
class Esdm_Tls_Credentials final : public Botan::Credentials_Manager {
    public:
	Esdm_Tls_Credentials(bool server, const struct esdm_tls_config *cfg,
			     const Botan::TLS::Policy &policy)
		: m_server(server)
	{
		/* Each file, see "Rollover of a CA" in esdm_tls.h */
		m_store = std::make_unique<Botan::Certificate_Store_In_Memory>();
		for (unsigned int i = 0; i < cfg->ca_files_num; i++) {
			for (const auto &ca :
			     esdm_tls_botan_load_certs(cfg->ca_files[i]))
				m_store->add_certificate(ca);
		}

		if (cfg->cert_file) {
			m_chain = esdm_tls_botan_load_certs(cfg->cert_file);
			check_signs(policy, cfg);
			load_key(cfg->key_file);
		}

		for (unsigned int i = 0; i < cfg->crl_files_num; i++)
			load_crls(cfg->crl_files[i]);
	}

	std::vector<Botan::X509_Certificate>
	find_cert_chain(const std::vector<std::string> &cert_key_types,
			const std::vector<Botan::AlgorithmIdentifier>
				&cert_signature_schemes,
			const std::vector<Botan::X509_DN> &acceptable_CAs,
			const std::string &type,
			const std::string &context) override
	{
		(void)cert_signature_schemes;
		(void)acceptable_CAs;
		(void)context;

		if (m_chain.empty() ||
		    type != (m_server ? "tls-server" : "tls-client"))
			return {};
		for (const auto &kt : cert_key_types) {
			if (kt == m_key->algo_name())
				return m_chain;
		}
		return {};
	}

	std::shared_ptr<Botan::Private_Key>
	private_key_for(const Botan::X509_Certificate &cert,
			const std::string &type,
			const std::string &context) override
	{
		(void)type;
		(void)context;

		if (!m_chain.empty() && cert == m_chain[0])
			return m_key;
		return nullptr;
	}

	std::vector<Botan::Certificate_Store *>
	trusted_certificate_authorities(const std::string &type,
					const std::string &context) override
	{
		(void)type;
		(void)context;

		return { m_store.get() };
	}

	Botan::Certificate_Store &store()
	{
		return *m_store;
	}

	const std::vector<Botan::X509_Certificate> &chain() const
	{
		return m_chain;
	}

	std::vector<Botan::X509_CRL> m_crls;

    private:
	/*
	 * The key of the own certificate signs the handshake, see
	 * esdm_tls_botan_signs() - told before the key is read, which Botan
	 * may not even parse for an algorithm it has no scheme for
	 */
	void check_signs(const Botan::TLS::Policy &policy,
			 const struct esdm_tls_config *cfg)
	{
		const std::string algo =
			m_chain[0].subject_public_key()->algo_name();

		if (esdm_tls_botan_signs(policy, algo))
			return;
		throw Botan::Invalid_Argument(
			"the certificate " + std::string(cfg->cert_file) +
			" is one of " + algo + ", which Botan " +
			Botan::short_version_string() +
			" has no signature scheme of TLS 1.3 for");
	}

	void load_key(const std::string &path)
	{
		/*
		 * Both hold the PEM in a secure_vector, wiped as they go out
		 * of scope, whether the key loads or throws
		 */
		Botan::secure_vector<uint8_t> pem =
			esdm_tls_botan_read_secret(path);
		Botan::DataSource_Memory src(pem.data(), pem.size());

		m_key = Botan::PKCS8::load_key(src);

		/* Both encoded by Botan, in the same way */
		if (m_chain[0].subject_public_key()->public_key_bits() !=
		    m_key->public_key_bits())
			throw Botan::Invalid_Argument(
				"the key " + path +
				" does not belong to the certificate");
	}

	void load_crls(const std::string &path)
	{
		size_t found = 0;

		for (const auto &block : esdm_tls_botan_pem_blocks(
			     esdm_tls_botan_read(path), "X509 CRL")) {
			Botan::DataSource_Memory src(block);

			m_crls.emplace_back(src);
			found++;
		}
		if (!found)
			throw Botan::Decoding_Error("no CRL in " + path);
	}

	bool m_server;
	std::unique_ptr<Botan::Certificate_Store_In_Memory> m_store;
	std::vector<Botan::X509_Certificate> m_chain;
	std::shared_ptr<Botan::Private_Key> m_key;
};

/*
 * Is the certificate of the server issued for @name? An address literal is
 * looked for among the IP addresses of the subject alternative name, which
 * takes the typed interface of Botan 3.13 for IPv6.
 */
static bool esdm_tls_botan_name_matches(const Botan::X509_Certificate &cert,
					const std::string &name)
{
	unsigned char addr[sizeof(struct in6_addr)];

	if (inet_pton(AF_INET6, name.c_str(), addr) == 1) {
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
		auto ip = Botan::IPv6Address::from_string(name);

		return ip.has_value() && cert.matches_ip(*ip);
#else
		throw Botan::Invalid_Argument(
			"an IPv6 address as server name needs Botan 3.13");
#endif
	}

	/* A DNS name, or an IPv4 address in dotted quad notation */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return cert.matches_dns_name(name);
#pragma GCC diagnostic pop
}

/* The alert of a verdict of the revocation policy */
static Botan::TLS::Alert::Type esdm_tls_botan_verdict_alert(
	enum esdm_tls_verdict verdict)
{
	switch (verdict) {
	case esdm_tls_verdict_revoked:
		return Botan::TLS::Alert::CertificateRevoked;
	case esdm_tls_verdict_crl_expired:
		return Botan::TLS::Alert::CertificateExpired;
	case esdm_tls_verdict_no_crl:
		return Botan::TLS::Alert::UnknownCA;
	case esdm_tls_verdict_accepted:
	case esdm_tls_verdict_bad_chain:
	default:
		return Botan::TLS::Alert::BadCertificate;
	}
}

/*
 * The revocation policy on the path Botan verified, which ends in a trust
 * anchor: a refusal is an exception whose alert Botan sends.
 */
static void
esdm_tls_botan_check(Esdm_Tls_Callbacks &cb,
		     const std::vector<Botan::X509_Certificate> &path)
{
	enum esdm_tls_verdict verdict;
	struct esdm_tls_der *chain;
	size_t i, n = path.size();

	if (!n || n > ESDM_TLS_MAX_CHAIN) {
		cb.m_error = "certificate verify failed: chain too long";
		throw Botan::TLS::TLS_Exception(
			Botan::TLS::Alert::BadCertificate, cb.m_error);
	}

	chain = static_cast<struct esdm_tls_der *>(calloc(n, sizeof(*chain)));
	if (!chain)
		throw std::bad_alloc();
	try {
		for (i = 0; i < n; i++) {
			std::vector<uint8_t> der = path[i].BER_encode();

			chain[i].data =
				static_cast<uint8_t *>(malloc(der.size()));
			if (!chain[i].data)
				throw std::bad_alloc();
			std::memcpy(chain[i].data, der.data(), der.size());
			chain[i].len = der.size();
		}
	} catch (...) {
		for (i = 0; i < n; i++)
			free(chain[i].data);
		free(chain);
		throw;
	}

	/* The policy takes the chain over */
	verdict = cb.m_check(cb.m_check_arg, chain, n);
	if (verdict != esdm_tls_verdict_accepted) {
		cb.m_error = "certificate refused by the revocation policy";
		throw Botan::TLS::TLS_Exception(
			esdm_tls_botan_verdict_alert(verdict), cb.m_error);
	}
}

/*
 * The chain of the peer: its path to a trust anchor and its usage, the name of
 * the server, and the revocation policy on the path - see the file header
 */
static void esdm_tls_botan_verify(
	Esdm_Tls_Callbacks &cb,
	const std::vector<Botan::X509_Certificate> &cert_chain,
	const std::vector<std::optional<Botan::OCSP::Response> > &ocsp_responses,
	const std::vector<Botan::Certificate_Store *> &trusted_roots,
	Botan::Usage_Type usage, const Botan::TLS::Policy &policy)
{
	if (cert_chain.empty())
		throw Botan::TLS::TLS_Exception(
			Botan::TLS::Alert::BadCertificate,
			"the peer presented no certificate");

	/*
	 * The chain and its usage, without a name - which is checked below.
	 * Revocation is the business of esdm_tls.c.
	 */
	Botan::Path_Validation_Restrictions restrictions(
		false, policy.minimum_signature_strength());
	Botan::Path_Validation_Result result = Botan::x509_path_validate(
		cert_chain, restrictions, trusted_roots, "", usage,
		cb.tls_current_timestamp(),
		cb.tls_verify_cert_chain_ocsp_timeout(), ocsp_responses);

	if (!result.successful_validation()) {
		cb.m_error =
			"certificate verify failed: " + result.result_string();
		throw Botan::TLS::TLS_Exception(
			Botan::TLS::Alert::BadCertificate, cb.m_error);
	}

	if (!cb.m_server &&
	    !esdm_tls_botan_name_matches(cert_chain[0], cb.m_server_name)) {
		cb.m_error = "certificate verify failed: not issued for " +
			     cb.m_server_name;
		throw Botan::TLS::TLS_Exception(
			Botan::TLS::Alert::BadCertificate, cb.m_error);
	}

	esdm_tls_botan_check(cb, result.cert_path());
}

#endif /* ESDM_TLS_AUTH */

} // namespace

/******************************************************************************
 * esdm_tls_backend.h: the core
 ******************************************************************************/

extern "C" {

const char *esdm_tls_backend_name(void)
{
	return "Botan";
}

int esdm_tls_backend_ctx_new(bool server, enum esdm_tls_transport transport,
			     void **ctx)
{
	bool dgram = transport == ESDM_TLS_TRANSPORT_SEQPACKET;

	if (!dgram && transport != ESDM_TLS_TRANSPORT_STREAM)
		return -EINVAL;
#ifndef ESDM_DTLS
	if (dgram)
		return -EOPNOTSUPP;
#endif
#ifndef ESDM_TLS_AUTH
	if (!dgram)
		return -EOPNOTSUPP;
#endif

	try {
		/*
		 * The allocator of Botan's secure memory, which a context of
		 * a client does not need yet: set up now, its static
		 * destructor runs after the exit handler esdm_tls.c or
		 * esdm_dtls.c registers next - see esdm_tls_exiting() and
		 * esdm_dtls_exiting() there.
		 */
		Botan::secure_vector<uint8_t> allocator(1);
		auto c = std::make_unique<Esdm_Tls_Ctx>();

		c->server = server;
		c->dgram = dgram;
		c->rng = std::make_shared<Botan::System_RNG>();
		c->policy =
			std::make_shared<const Esdm_Tls_Policy>(server, dgram);
#ifdef ESDM_DTLS
		if (dgram)
			c->creds = std::make_shared<Esdm_Tls_Psk_Credentials>();
		else
#endif
			/* None until the files are loaded */
			c->creds =
				std::make_shared<Botan::Credentials_Manager>();
		c->sessions =
			std::make_shared<Botan::TLS::Session_Manager_Noop>();

		*ctx = c.release();
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

void esdm_tls_backend_ctx_free(void *ctx)
{
	delete static_cast<Esdm_Tls_Ctx *>(ctx);
}

int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	try {
		auto d = std::make_unique<Esdm_Tls_Conn>();
		unsigned char addr[sizeof(struct in6_addr)];

		d->callbacks = std::make_shared<Esdm_Tls_Callbacks>(
			fd, c->dgram, server, server_name, check, arg,
			c->verify);
		if (server) {
			d->channel = std::make_unique<Botan::TLS::Server>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, c->dgram);
		} else {
			/*
			 * An address literal is no server name to indicate -
			 * the name is checked in esdm_tls_botan_verify()
			 * either way -, and the local DTLS has none. The
			 * ClientHello is emitted right away.
			 */
			bool name =
				server_name &&
				inet_pton(AF_INET, server_name, addr) != 1 &&
				inet_pton(AF_INET6, server_name, addr) != 1;

			d->channel = std::make_unique<Botan::TLS::Client>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng,
				name ? Botan::TLS::Server_Information(
					       server_name) :
				       Botan::TLS::Server_Information(),
				c->dgram ?
					Botan::TLS::Protocol_Version::DTLS_V12 :
					Botan::TLS::Protocol_Version::TLS_V13);
		}

		*conn = d.release();
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

void esdm_tls_backend_conn_free(void *conn)
{
	delete static_cast<Esdm_Tls_Conn *>(conn);
}

int esdm_tls_backend_handshake(void *conn, short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		auto &cb = *c->callbacks;
		int ret;

		for (;;) {
			ret = cb.flush();
			if (ret == -EAGAIN) {
				*want = POLLOUT;
				return -EAGAIN;
			}
			if (ret)
				return ret;

			/*
			 * Complete once the last flight of ours is out, too.
			 * Not merely active: a TLS 1.3 server is so before
			 * the client's certificate and Finished arrived.
			 */
			if (c->channel->is_handshake_complete())
				return 0;
			if (cb.m_fatal)
				return esdm_tls_botan_alert_error(c);
			if (cb.m_peer_closed || c->channel->is_closed()) {
				if (cb.m_error.empty())
					cb.m_error =
						"connection closed by the peer";
				return -ECONNRESET;
			}

			ret = esdm_tls_botan_feed(c);
			if (ret == -EAGAIN) {
				if (cb.out_pending())
					continue;
				*want = POLLIN;
				return -EAGAIN;
			}
			if (ret)
				return ret;
		}
	} catch (const std::exception &e) {
		c->callbacks->set_error(e.what());
		return -EPROTO;
	} catch (...) {
		return -EPROTO;
	}
}

ssize_t esdm_tls_backend_send(void *conn, const uint8_t *buf, size_t len,
			      short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		auto &cb = *c->callbacks;
		int ret;

		/* Taking more while the socket is full would buffer it here */
		ret = cb.flush();
		if (ret == -EAGAIN) {
			*want = POLLOUT;
			return -EAGAIN;
		}
		if (ret)
			return ret;

		if (cb.m_fatal)
			return esdm_tls_botan_alert_error(c);
		if (!c->channel->is_active())
			return -ECONNRESET;

		c->channel->send(std::span<const uint8_t>(buf, len));

		/* Taken, whatever of it the socket takes right now */
		ret = cb.flush();
		if (ret && ret != -EAGAIN)
			return ret;

		return static_cast<ssize_t>(len);
	} catch (const std::exception &e) {
		c->callbacks->set_error(e.what());
		return -EPROTO;
	} catch (...) {
		return -EPROTO;
	}
}

int esdm_tls_backend_flush(void *conn, short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	/* Throws nothing */
	int ret = c->callbacks->flush();

	if (ret == -EAGAIN)
		*want = POLLOUT;
	return ret;
}

ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len, short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		auto &cb = *c->callbacks;
		size_t n;

		if (!cb.has_data()) {
			int ret;

			if (cb.m_fatal)
				return esdm_tls_botan_alert_error(c);
			if (cb.m_peer_closed)
				return 0;

			ret = esdm_tls_botan_feed(c);
			if (!cb.has_data()) {
				if (cb.m_peer_closed && !cb.m_fatal)
					return 0;
				/* A record without data: more to come */
				if (ret == -EAGAIN || !ret) {
					*want = POLLIN;
					return -EAGAIN;
				}
				return ret;
			}
		}

		/* SOCK_SEQPACKET: a record whole, or none */
		if (cb.m_dgram) {
			std::vector<uint8_t> rec =
				std::move(cb.m_records.front());

			cb.m_records.pop_front();
			n = rec.size();
			if (n <= len)
				std::memcpy(buf, rec.data(), n);
			memset_secure(rec.data(), 0, rec.size());
			if (n > len) {
				cb.set_error("a record larger than the buffer");
				return -EMSGSIZE;
			}
			return static_cast<ssize_t>(n);
		}

		n = cb.m_in.size() - cb.m_in_off;
		if (n > len)
			n = len;
		std::memcpy(buf, cb.m_in.data() + cb.m_in_off, n);
		cb.m_in_off += n;

		/* Used up: wiped, and the room reused */
		if (cb.m_in_off >= cb.m_in.size()) {
			memset_secure(cb.m_in.data(), 0, cb.m_in.size());
			cb.m_in.clear();
			cb.m_in_off = 0;
		}

		return static_cast<ssize_t>(n);
	} catch (const std::exception &e) {
		c->callbacks->set_error(e.what());
		return -EPROTO;
	} catch (...) {
		return -EPROTO;
	}
}

bool esdm_tls_backend_pending(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->has_data();
}

void esdm_tls_backend_close_notify(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		if (c->channel->is_active())
			c->channel->close();
		c->callbacks->flush();
	} catch (...) {
	}
}

const char *esdm_tls_backend_cipher(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->m_cipher.c_str();
}

const char *esdm_tls_backend_group(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->m_group.empty() ? nullptr :
					       c->callbacks->m_group.c_str();
}

const char *esdm_tls_backend_error(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->m_error.c_str();
}

#ifdef ESDM_TLS_AUTH

/******************************************************************************
 * esdm_tls_backend.h: the certificates
 ******************************************************************************/

int esdm_tls_backend_ctx_files(void *ctx, bool server,
			       const struct esdm_tls_config *cfg)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	if (c->dgram)
		return -EINVAL;

	try {
		/* The files, the same on either side */
		auto files = std::make_shared<Esdm_Tls_Credentials>(server, cfg,
								    *c->policy);

		/* The own certificate has to chain to the trust anchors */
		if (!files->chain().empty()) {
			Botan::Path_Validation_Restrictions restrictions;
			Botan::Path_Validation_Result result =
				Botan::x509_path_validate(files->chain(),
							  restrictions,
							  files->store());

			/*
			 * The chain, not the time - see "Contexts" in
			 * esdm_tls.h. The overall status is the worst one
			 * found, so one about the time only means nothing else
			 * is wrong.
			 */
			auto status = result.result();

			if (!result.successful_validation() &&
			    status != Botan::Certificate_Status_Code::
					      CERT_HAS_EXPIRED &&
			    status != Botan::Certificate_Status_Code::
					      CERT_NOT_YET_VALID) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_ANY,
					"TLS: the certificate %s does not chain to the trust anchors %s%s: %s\n",
					cfg->cert_file, ESDM_TLS_CAS_FMT(cfg),
					result.result_string().c_str());
				return -EINVAL;
			}
		}

		c->files = files;
		c->creds = files;
		c->verify = esdm_tls_botan_verify;
		return 0;
	} catch (const std::bad_alloc &) {
		return -ENOMEM;
	} catch (const std::exception &e) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot load the files of the %s: %s\n",
			    server ? "server" : "client", e.what());
		return -EINVAL;
	}
}

size_t esdm_tls_backend_crl_count(void *ctx)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	return c->files ? c->files->m_crls.size() : 0;
}

int esdm_tls_backend_crl_info(void *ctx, size_t idx,
			      struct esdm_tls_crl_info *info)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	if (!c->files || idx >= c->files->m_crls.size())
		return -ENOENT;

	try {
		const auto &crl = c->files->m_crls[idx];

		std::snprintf(info->issuer, sizeof(info->issuer), "%s",
			      crl.issuer_dn().to_string().c_str());
		info->next_update = crl.next_update().time_is_set() ?
					    static_cast<int64_t>(
						    crl.next_update()
							    .time_since_epoch()) :
					    0;
		info->delta = crl.extensions().extension_set(
			Botan::OID::from_string("2.5.29.27"));
		info->scoped = crl.extensions().extension_set(
			Botan::OID::from_string("2.5.29.28"));
		return 0;
	} catch (...) {
		return -EINVAL;
	}
}

int esdm_tls_backend_crl_lookup(void *ctx, const struct esdm_tls_der *cert,
				const struct esdm_tls_der *issuer,
				struct esdm_tls_crl_result *res)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	std::memset(res, 0, sizeof(*res));
	if (!c->files)
		return 0;

	try {
		Botan::X509_Certificate x(
			std::vector<uint8_t>(cert->data, cert->data + cert->len));
		Botan::X509_Certificate iss(std::vector<uint8_t>(
			issuer->data, issuer->data + issuer->len));
		auto key = iss.subject_public_key();
		const Botan::X509_CRL *best = nullptr;

		for (const auto &crl : c->files->m_crls) {
			if (crl.issuer_dn() != iss.subject_dn())
				continue;
			if (!crl.check_signature(*key))
				continue;

			/* Of several, the one issued last */
			if (best && crl.this_update().time_since_epoch() <=
					    best->this_update().time_since_epoch())
				continue;
			best = &crl;
		}

		if (!best)
			return 0;

		res->found = true;
		res->next_update =
			best->next_update().time_is_set() ?
				static_cast<int64_t>(
					best->next_update().time_since_epoch()) :
				0;
		res->revoked = best->is_revoked(x);
		return 0;
	} catch (...) {
		return -EINVAL;
	}
}

int esdm_tls_backend_cert_info(const struct esdm_tls_der *cert,
			       struct esdm_tls_cert_info *info)
{
	try {
		Botan::X509_Certificate x(
			std::vector<uint8_t>(cert->data, cert->data + cert->len));
		const auto &serial = x.serial_number();
		size_t i;

		std::snprintf(info->subject, sizeof(info->subject), "%s",
			      x.subject_dn().to_string().c_str());
		info->not_after =
			static_cast<int64_t>(x.not_after().time_since_epoch());

		std::snprintf(info->serial, sizeof(info->serial), "unknown");
		if (2 * serial.size() < sizeof(info->serial)) {
			for (i = 0; i < serial.size(); i++)
				std::snprintf(info->serial + 2 * i, 3, "%02X",
					      serial[i]);
		}

		/* Told whether Botan has the algorithm or not */
		const std::string oid =
			x.subject_public_key_algo().oid().to_string();

		info->key_oid[0] = '\0';
		if (oid.size() < sizeof(info->key_oid))
			std::snprintf(info->key_oid, sizeof(info->key_oid),
				      "%s", oid.c_str());
		return 0;
	} catch (...) {
		return -EINVAL;
	}
}

/* The hybrid of ML-KEM, if Botan has it, as Botan names it */
const char *esdm_tls_backend_mlkem_group(void)
{
	try {
		static const std::string name = []() {
			const auto hybrid = esdm_tls_botan_hybrid();

			return hybrid ? hybrid->to_string().value_or("") :
					std::string();
		}();

		return name.empty() ? nullptr : name.c_str();
	} catch (...) {
		return nullptr;
	}
}

/* From 3.13 on, see esdm_tls_botan_name_matches() */
bool esdm_tls_backend_ip6_name(void)
{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
	return true;
#else
	return false;
#endif
}

#endif /* ESDM_TLS_AUTH */

} /* extern "C" */
