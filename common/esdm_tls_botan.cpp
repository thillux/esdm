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
 * TLS of esdm_tls_backend.h by Botan, for crypto_backend=botan: TLS 1.3 on a
 * stream socket, DTLS 1.2 on SCTP - with the same files, the same
 * verification and the same revocation policy, see Esdm_Tls_Credentials and
 * tls_verify_cert_chain().
 *
 * A Botan TLS channel does no I/O of its own: what it has to send it hands to
 * tls_emit_data(), which is collected here and pushed to the socket by
 * esdm_tls_botan_flush() as far as the socket takes it - the rest waits for
 * the socket to become writable, see esdm_tls_backend_flush(). What the socket
 * has is fed to the channel with received_data(), and the application data of
 * a record comes back through tls_record_received(), which collects it here
 * until esdm_tls_backend_recv() hands it out. On SCTP, what is emitted goes to
 * the association of esdm_tls_sctp.h, which sends each record as a user
 * message of its own, and every user message received is fed whole; the
 * records received are kept apart, one per esdm_tls_backend_recv().
 *
 * The key of SCTP-AUTH is exported in the middle of the handshake - see
 * esdm_tls_sctp.h -, which key_material_export() of a channel does not do: it
 * takes a channel that is active. The key is computed here as Botan computes
 * it, with the PRF of the cipher suite over the master secret - handed out by
 * tls_ssl_key_log_data() as soon as it is derived - and the random values of
 * the hellos, as RFC 5705 has it. Once the handshake is complete, the key is
 * compared with what key_material_export() makes of it: the connection fails
 * if they differ.
 *
 * The certificate chain of the peer is verified here, in
 * tls_verify_cert_chain(), rather than by Botan's default: that one checks the
 * server name the client indicates, which an address literal is not - see
 * esdm_tls_botan_name_matches() - and does not hand out the path it verified,
 * which the revocation policy of esdm_tls.c is run on right there.
 *
 * No exception crosses into the C code: every entry point catches them and
 * reports an errno.
 */

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

#include <botan/certstor.h>
#include <botan/data_src.h>
#include <botan/kdf.h>
#include <botan/pkcs8.h>
#include <botan/secmem.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
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
 * TLS 1.3 exactly on a stream socket, DTLS 1.2 exactly on SCTP - there with
 * ECDHE and AEAD ciphers only, the MTU of RFC 6083 and no cookie exchange,
 * which SCTP has its own of. No resumption nor renegotiation, and a server that
 * requires a certificate.
 */
class Esdm_Tls_Policy final : public Botan::TLS::Policy {
    public:
	Esdm_Tls_Policy(bool server, bool sctp)
		: m_server(server), m_sctp(sctp)
	{
	}

	bool allow_tls12() const override
	{
		return false;
	}

	bool allow_tls13() const override
	{
		return !m_sctp;
	}

	bool allow_dtls12() const override
	{
		return m_sctp;
	}

	std::vector<std::string> allowed_ciphers() const override
	{
		if (!m_sctp)
			return Botan::TLS::Policy::allowed_ciphers();
		return { "AES-256/GCM", "ChaCha20Poly1305", "AES-128/GCM" };
	}

	std::vector<std::string> allowed_macs() const override
	{
		if (!m_sctp)
			return Botan::TLS::Policy::allowed_macs();
		return { "AEAD" };
	}

	std::vector<std::string> allowed_key_exchange_methods() const override
	{
		if (!m_sctp)
			return Botan::TLS::Policy::allowed_key_exchange_methods();
		return { "ECDH" };
	}

	bool require_client_certificate_authentication() const override
	{
		return m_server;
	}

	bool allow_client_initiated_renegotiation() const override
	{
		return false;
	}

	bool allow_server_initiated_renegotiation() const override
	{
		return false;
	}

	size_t new_session_tickets_upon_handshake_success() const override
	{
		return 0;
	}

	size_t dtls_default_mtu() const override
	{
		return ESDM_TLS_SCTP_MTU;
	}

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
	bool dtls_server_require_cookie_exchange() const override
	{
		return false;
	}
#endif

	/*
	 * The master secret for the key of SCTP-AUTH, which is all the key log
	 * is used for - nothing is logged, see the file header
	 */
	bool allow_ssl_key_log_file() const override
	{
		return m_sctp;
	}

    private:
	bool m_server;
	bool m_sctp;
};

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

/* The own certificate and key, and the trust anchors and CRLs */
class Esdm_Tls_Credentials final : public Botan::Credentials_Manager {
    public:
	Esdm_Tls_Credentials(bool server, const struct esdm_tls_config *cfg)
		: m_server(server)
	{
		m_store = std::make_unique<Botan::Certificate_Store_In_Memory>();
		for (const auto &ca : esdm_tls_botan_load_certs(cfg->ca_file))
			m_store->add_certificate(ca);

		if (cfg->cert_file) {
			m_chain = esdm_tls_botan_load_certs(cfg->cert_file);
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
	void load_key(const std::string &path)
	{
		std::string text = esdm_tls_botan_read(path);
		Botan::DataSource_Memory src(text);

		m_key = Botan::PKCS8::load_key(src);
		memset_secure(text.data(), 0, text.size());

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

struct Esdm_Tls_Ctx {
	bool server;
	bool sctp;
	std::shared_ptr<Botan::RandomNumberGenerator> rng;
	std::shared_ptr<Esdm_Tls_Credentials> creds;
	std::shared_ptr<const Esdm_Tls_Policy> policy;
	std::shared_ptr<Botan::TLS::Session_Manager_Noop> sessions;
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

/* The connection as the channel sees it */
class Esdm_Tls_Callbacks final : public Botan::TLS::Callbacks {
    public:
	Esdm_Tls_Callbacks(int fd, struct esdm_tls_sctp *sctp, bool server,
			   const char *server_name,
			   esdm_tls_backend_check check, void *check_arg)
		: m_fd(fd), m_sctp(sctp), m_server(server),
		  m_server_name(server_name ? server_name : ""),
		  m_check(check), m_check_arg(check_arg)
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

	void tls_emit_data(std::span<const uint8_t> data) override
	{
		if (!m_sctp) {
			m_out.insert(m_out.end(), data.begin(), data.end());
			return;
		}

		/* Told to the caller once the channel returns */
		int ret = esdm_tls_sctp_queue(m_sctp, data.data(),
					      data.size());
		if (ret && !m_queue_error)
			m_queue_error = ret;
	}

	void tls_record_received(uint64_t seq_no,
				 std::span<const uint8_t> data) override
	{
		(void)seq_no;
		if (m_sctp)
			m_records.emplace_back(data.begin(), data.end());
		else
			m_in.insert(m_in.end(), data.begin(), data.end());
	}

	/* The master secret, for the key of SCTP-AUTH - see the file header */
	void tls_ssl_key_log_data(std::string_view label,
				  std::span<const uint8_t> client_random,
				  std::span<const uint8_t> secret) const override
	{
		if (!m_sctp || label != "CLIENT_RANDOM")
			return;
		m_master.assign(secret.begin(), secret.end());
		m_client_random.assign(client_random.begin(),
				       client_random.end());
	}

	/*
	 * The random value of the server and the cipher suite, for the same.
	 * The random value is not public: it is taken from the encoding of the
	 * message, where it follows the version (RFC 5246 section 7.4.1.3).
	 */
	void tls_inspect_handshake_msg(
		const Botan::TLS::Handshake_Message &message) override
	{
		const auto *hello =
			dynamic_cast<const Botan::TLS::Server_Hello *>(&message);

		if (!m_sctp)
			return;

		/*
		 * A Certificate of DTLS 1.2 with no certificate in it - three
		 * bytes of an empty list - is the client's, which a server
		 * refuses with an alert of a handshake failure: a refused
		 * certificate all the same, see esdm_tls_botan_alert_error()
		 */
		if (m_server &&
		    message.type() == Botan::TLS::Handshake_Type::Certificate &&
		    message.serialize().size() <= 3)
			m_peer_no_cert = true;

		if (!hello)
			return;

		std::vector<uint8_t> body = hello->serialize();
		if (body.size() < 2 + 32)
			return;
		m_server_random.assign(body.begin() + 2, body.begin() + 2 + 32);
		m_ciphersuite = hello->ciphersuite();
	}

	/*
	 * The exporter of RFC 5705 without a context, as key_material_export()
	 * computes it: the PRF of the cipher suite over the master secret, the
	 * label and the random values of the client and the server.
	 */
	int export_key(std::string_view label, uint8_t *out,
		       size_t len) const
	{
		if (m_master.empty() || m_client_random.empty() ||
		    m_server_random.empty())
			return -EAGAIN;

		auto suite = Botan::TLS::Ciphersuite::by_id(m_ciphersuite);
		if (!suite)
			return -EINVAL;
		auto prf = Botan::KDF::create_or_throw("TLS-12-PRF(" +
						       suite->prf_algo() + ")");

		std::vector<uint8_t> salt(m_client_random);
		salt.insert(salt.end(), m_server_random.begin(),
			    m_server_random.end());

		Botan::secure_vector<uint8_t> key = prf->derive_key(
			len, m_master, salt,
			std::span<const uint8_t>(
				reinterpret_cast<const uint8_t *>(label.data()),
				label.size()));
		std::memcpy(out, key.data(), len);
		return 0;
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

	void tls_session_established(
		const Botan::TLS::Session_Summary &session) override
	{
		m_cipher = session.ciphersuite().to_string();
	}

	void tls_verify_cert_chain(
		const std::vector<Botan::X509_Certificate> &cert_chain,
		const std::vector<std::optional<Botan::OCSP::Response> >
			&ocsp_responses,
		const std::vector<Botan::Certificate_Store *> &trusted_roots,
		Botan::Usage_Type usage, std::string_view hostname,
		const Botan::TLS::Policy &policy) override
	{
		(void)hostname;

		if (cert_chain.empty())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::BadCertificate,
				"the peer presented no certificate");

		/*
		 * The chain and its usage, without a name - which is checked
		 * below. Revocation is the business of esdm_tls.c.
		 */
		Botan::Path_Validation_Restrictions restrictions(
			false, policy.minimum_signature_strength());
		Botan::Path_Validation_Result result = Botan::x509_path_validate(
			cert_chain, restrictions, trusted_roots, "", usage,
			tls_current_timestamp(),
			tls_verify_cert_chain_ocsp_timeout(), ocsp_responses);

		if (!result.successful_validation()) {
			m_error = "certificate verify failed: " +
				  result.result_string();
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::BadCertificate, m_error);
		}

		if (!m_server &&
		    !esdm_tls_botan_name_matches(cert_chain[0],
						 m_server_name)) {
			m_error = "certificate verify failed: not issued for " +
				  m_server_name;
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::BadCertificate, m_error);
		}

		check(result.cert_path());
	}

	/*
	 * The revocation policy on the path Botan verified, which ends in a
	 * trust anchor: a refusal is an exception whose alert Botan sends.
	 */
	void check(const std::vector<Botan::X509_Certificate> &path)
	{
		enum esdm_tls_verdict verdict;
		struct esdm_tls_der *chain;
		size_t i, n = path.size();

		if (!n || n > ESDM_TLS_MAX_CHAIN) {
			m_error = "certificate verify failed: chain too long";
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::BadCertificate, m_error);
		}

		chain = static_cast<struct esdm_tls_der *>(
			calloc(n, sizeof(*chain)));
		if (!chain)
			throw std::bad_alloc();
		try {
			for (i = 0; i < n; i++) {
				std::vector<uint8_t> der = path[i].BER_encode();

				chain[i].data = static_cast<uint8_t *>(
					malloc(der.size()));
				if (!chain[i].data)
					throw std::bad_alloc();
				std::memcpy(chain[i].data, der.data(),
					    der.size());
				chain[i].len = der.size();
			}
		} catch (...) {
			for (i = 0; i < n; i++)
				free(chain[i].data);
			free(chain);
			throw;
		}

		/* The policy takes the chain over */
		verdict = m_check(m_check_arg, chain, n);
		if (verdict != esdm_tls_verdict_accepted) {
			m_error = "certificate refused by the revocation policy";
			throw Botan::TLS::TLS_Exception(
				esdm_tls_botan_verdict_alert(verdict), m_error);
		}
	}

	/*
	 * Push out what the channel emitted, as far as the socket takes it.
	 * Throws nothing.
	 *
	 * @return 0 when all is out, -EAGAIN if not, a negative errno
	 */
	int flush() noexcept
	{
		while (m_out_off < m_out.size()) {
			ssize_t n = send(m_fd, m_out.data() + m_out_off,
					 m_out.size() - m_out_off,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (n < 0) {
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
			m_out_off += static_cast<size_t>(n);
		}

		memset_secure(m_out.data(), 0, m_out.size());
		m_out.clear();
		m_out_off = 0;
		return 0;
	}

	bool out_pending() const
	{
		return m_out_off < m_out.size();
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
	struct esdm_tls_sctp *m_sctp;
	int m_queue_error = 0;
	/* SCTP: the client presented no certificate */
	bool m_peer_no_cert = false;
	bool m_server;
	std::string m_server_name;
	esdm_tls_backend_check m_check;
	void *m_check_arg;

	std::vector<uint8_t> m_out;
	size_t m_out_off = 0;
	std::vector<uint8_t> m_in;
	size_t m_in_off = 0;

	/* SCTP: the records received, and what the key of SCTP-AUTH takes */
	std::deque<std::vector<uint8_t> > m_records;
	mutable Botan::secure_vector<uint8_t> m_master;
	mutable std::vector<uint8_t> m_client_random;
	std::vector<uint8_t> m_server_random;
	uint16_t m_ciphersuite = 0;

	bool m_peer_closed = false;
	bool m_eof = false;
	/*
	 * The channel is dead: a fatal alert of the peer, or one it sent for
	 * what it got - m_alert tells which
	 */
	bool m_fatal = false;
	Botan::TLS::Alert::Type m_alert = Botan::TLS::Alert::CloseNotify;
	std::string m_cipher = "unknown";
	std::string m_error;
};

struct Esdm_Tls_Conn {
	std::shared_ptr<Esdm_Tls_Callbacks> callbacks;
	std::unique_ptr<Botan::TLS::Channel> channel;
};

/* A fatal alert of the peer, or one that ended the channel here */
static int esdm_tls_botan_alert_error(Esdm_Tls_Conn *c)
{
	/* No certificate is a handshake failure to DTLS 1.2, see above */
	if (c->callbacks->m_peer_no_cert)
		return -EACCES;
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
	if (cb.m_queue_error)
		return cb.m_queue_error;
	return 0;
}

/*
 * SCTP: feed the channel the user messages of the association, each whole,
 * until there are none more or the channel has a record of application data.
 *
 * @return as esdm_tls_botan_feed()
 */
static int esdm_tls_botan_feed_sctp(Esdm_Tls_Conn *c)
{
	auto &cb = *c->callbacks;
	/* On the heap: a client may run on a thread with a small stack */
	std::vector<uint8_t> buf(ESDM_TLS_SCTP_MSG_MAX + 1);
	bool got = false;
	int ret = 0;

	while (cb.m_records.empty() && !cb.m_peer_closed) {
		ssize_t n = esdm_tls_sctp_recv(cb.m_sctp, buf.data(),
					       buf.size());

		if (n == -EAGAIN) {
			ret = got ? 0 : -EAGAIN;
			break;
		}
		if (n < 0) {
			if (n == -ECONNRESET) {
				cb.m_eof = true;
				if (cb.m_error.empty())
					cb.m_error =
						"connection closed by the peer without a closing alert";
			} else {
				cb.set_error(std::strerror((int)-n));
			}
			ret = (int)n;
			break;
		}

		got = true;
		ret = esdm_tls_botan_received(c, buf.data(),
					      static_cast<size_t>(n));
		if (ret)
			break;
	}

	memset_secure(buf.data(), 0, buf.size());
	return ret;
}

/*
 * Feed the channel what the socket has, until the socket has nothing more or
 * the channel has application data.
 *
 * @return 0 if the socket is drained or data is there, -EAGAIN if nothing was
 *	   there to be read, -ECONNRESET at the end of the stream, -EACCES or
 *	   -EPROTO if the channel refused what it got, another negative errno
 */
static int esdm_tls_botan_feed(Esdm_Tls_Conn *c)
{
	auto &cb = *c->callbacks;
	/* On the heap: a client may run on a thread with a small stack */
	std::vector<uint8_t> buf(16384 + 512);
	bool got = false;
	int ret = 0;

	while (cb.m_in_off >= cb.m_in.size() && !cb.m_peer_closed) {
		ssize_t n = recv(cb.m_fd, buf.data(), buf.size(), MSG_DONTWAIT);

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

		/*
		 * The channel sends the alert of what it throws, and is dead
		 * then - for good: every later call fails the same way.
		 */
		got = true;
		try {
			c->channel->received_data(std::span<const uint8_t>(
				buf.data(), static_cast<size_t>(n)));
		} catch (const Botan::TLS::TLS_Exception &e) {
			if (cb.m_error.empty())
				cb.m_error = e.what();
			cb.m_fatal = true;
			cb.m_alert = e.type();
			ret = esdm_tls_botan_alert_error(c);
			break;
		} catch (const std::bad_alloc &) {
			cb.m_fatal = true;
			cb.m_alert = Botan::TLS::Alert::InternalError;
			cb.set_error("out of memory");
			ret = -ENOMEM;
			break;
		} catch (const std::exception &e) {
			cb.m_fatal = true;
			cb.m_alert = Botan::TLS::Alert::DecodeError;
			if (cb.m_error.empty())
				cb.set_error(e.what());
			ret = -EPROTO;
			break;
		}

		if (cb.m_fatal) {
			ret = esdm_tls_botan_alert_error(c);
			break;
		}
	}

	memset_secure(buf.data(), 0, buf.size());

	/* Whatever the channel answered - alerts included - goes out */
	if (cb.flush() == -ECONNRESET && !ret)
		ret = -ECONNRESET;

	return ret;
}

} // namespace

/******************************************************************************
 * esdm_tls_backend.h
 ******************************************************************************/

extern "C" {

const char *esdm_tls_backend_name(void)
{
	return "Botan";
}

int esdm_tls_backend_ctx_new(bool server, const struct esdm_tls_config *cfg,
			     void **ctx)
{
	try {
		/*
		 * The allocator of Botan's secure memory, set up now - before
		 * the files may need it, should there be none - so that its
		 * static destructor runs after the exit handler esdm_tls.c
		 * registers next - see esdm_tls_exiting() there.
		 */
		Botan::secure_vector<uint8_t> allocator(1);
		auto c = std::make_unique<Esdm_Tls_Ctx>();

		c->server = server;
		c->sctp = cfg->transport == ESDM_TLS_TRANSPORT_SCTP;
		c->rng = std::make_shared<Botan::System_RNG>();
		/* The files, the same on either transport */
		c->creds = std::make_shared<Esdm_Tls_Credentials>(server, cfg);
		c->policy = std::make_shared<const Esdm_Tls_Policy>(server,
								     c->sctp);
		c->sessions =
			std::make_shared<Botan::TLS::Session_Manager_Noop>();

		/* The own certificate has to chain to the trust anchors */
		if (!c->creds->chain().empty()) {
			Botan::Path_Validation_Restrictions restrictions;
			Botan::Path_Validation_Result result =
				Botan::x509_path_validate(c->creds->chain(),
							  restrictions,
							  c->creds->store());

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
					"TLS: the certificate %s does not chain to the trust anchors %s: %s\n",
					cfg->cert_file, cfg->ca_file,
					result.result_string().c_str());
				return -EINVAL;
			}
		}

		*ctx = c.release();
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

void esdm_tls_backend_ctx_free(void *ctx)
{
	delete static_cast<Esdm_Tls_Ctx *>(ctx);
}

size_t esdm_tls_backend_crl_count(void *ctx)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	return c->creds->m_crls.size();
}

int esdm_tls_backend_crl_info(void *ctx, size_t idx,
			      struct esdm_tls_crl_info *info)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	if (idx >= c->creds->m_crls.size())
		return -ENOENT;

	try {
		const auto &crl = c->creds->m_crls[idx];

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

	try {
		Botan::X509_Certificate x(
			std::vector<uint8_t>(cert->data, cert->data + cert->len));
		Botan::X509_Certificate iss(std::vector<uint8_t>(
			issuer->data, issuer->data + issuer->len));
		auto key = iss.subject_public_key();
		const Botan::X509_CRL *best = nullptr;

		for (const auto &crl : c->creds->m_crls) {
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
		return 0;
	} catch (...) {
		return -EINVAL;
	}
}

int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      struct esdm_tls_sctp *sctp,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn)
{
	auto *c = static_cast<Esdm_Tls_Ctx *>(ctx);

	if (c->sctp != (sctp != nullptr))
		return -EINVAL;

	try {
		auto d = std::make_unique<Esdm_Tls_Conn>();
		unsigned char addr[sizeof(struct in6_addr)];

		d->callbacks = std::make_shared<Esdm_Tls_Callbacks>(
			fd, sctp, server, server_name, check, arg);
		if (server) {
			d->channel = std::make_unique<Botan::TLS::Server>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, c->sctp);
		} else {
			/*
			 * An address literal is no server name to indicate -
			 * the name is checked in tls_verify_cert_chain()
			 * either way. The ClientHello is emitted right away.
			 */
			bool literal =
				inet_pton(AF_INET, server_name, addr) == 1 ||
				inet_pton(AF_INET6, server_name, addr) == 1;

			d->channel = std::make_unique<Botan::TLS::Client>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng,
				literal ? Botan::TLS::Server_Information() :
					  Botan::TLS::Server_Information(
						  server_name),
				c->sctp ? Botan::TLS::Protocol_Version::DTLS_V12 :
					  Botan::TLS::Protocol_Version::TLS_V13);
		}

		/* The ClientHello, queued */
		if (d->callbacks->m_queue_error)
			return d->callbacks->m_queue_error;

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
			/* On SCTP, esdm_tls.c sends the queue */
			ret = cb.m_sctp ? cb.m_queue_error : cb.flush();
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

			ret = cb.m_sctp ? esdm_tls_botan_feed_sctp(c) :
					  esdm_tls_botan_feed(c);
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
		c->callbacks->m_error = e.what();
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

		/* One record, queued on SCTP - see esdm_tls_sctp.h */
		if (cb.m_sctp) {
			if (cb.m_fatal)
				return esdm_tls_botan_alert_error(c);
			if (!c->channel->is_active())
				return -ECONNRESET;
			c->channel->send(std::span<const uint8_t>(buf, len));
			if (cb.m_queue_error)
				return cb.m_queue_error;
			return static_cast<ssize_t>(len);
		}

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
		c->callbacks->m_error = e.what();
		return -EPROTO;
	} catch (...) {
		return -EPROTO;
	}
}

int esdm_tls_backend_flush(void *conn, short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	/* On SCTP, esdm_tls.c sends the queue */
	if (c->callbacks->m_sctp)
		return 0;

	/* Throws nothing */
	int ret = c->callbacks->flush();

	if (ret == -EAGAIN)
		*want = POLLOUT;
	return ret;
}

ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len,
			      short *want)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		auto &cb = *c->callbacks;
		size_t n;

		/* SCTP: one record, whole */
		if (cb.m_sctp) {
			if (cb.m_records.empty()) {
				int ret;

				if (cb.m_fatal)
					return esdm_tls_botan_alert_error(c);
				if (cb.m_peer_closed)
					return 0;

				ret = esdm_tls_botan_feed_sctp(c);
				if (cb.m_records.empty()) {
					if (cb.m_peer_closed && !cb.m_fatal)
						return 0;
					if (ret == -EAGAIN || !ret) {
						*want = POLLIN;
						return -EAGAIN;
					}
					return ret;
				}
			}

			std::vector<uint8_t> rec =
				std::move(cb.m_records.front());

			cb.m_records.pop_front();
			if (rec.size() > len) {
				memset_secure(rec.data(), 0, rec.size());
				cb.set_error("a record larger than the buffer");
				return -EMSGSIZE;
			}
			std::memcpy(buf, rec.data(), rec.size());
			memset_secure(rec.data(), 0, rec.size());
			return static_cast<ssize_t>(rec.size());
		}

		if (cb.m_in_off >= cb.m_in.size()) {
			int ret;

			if (cb.m_fatal)
				return esdm_tls_botan_alert_error(c);
			if (cb.m_peer_closed)
				return 0;

			ret = esdm_tls_botan_feed(c);
			if (cb.m_in_off >= cb.m_in.size()) {
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
		c->callbacks->m_error = e.what();
		return -EPROTO;
	} catch (...) {
		return -EPROTO;
	}
}

bool esdm_tls_backend_pending(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	if (c->callbacks->m_sctp)
		return !c->callbacks->m_records.empty();
	return c->callbacks->m_in_off < c->callbacks->m_in.size();
}

void esdm_tls_backend_close_notify(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		if (c->channel->is_active())
			c->channel->close();
		/* On SCTP, esdm_tls.c sends the queue */
		if (!c->callbacks->m_sctp)
			c->callbacks->flush();
	} catch (...) {
	}
}

const char *esdm_tls_backend_cipher(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->m_cipher.c_str();
}

const char *esdm_tls_backend_error(void *conn)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	return c->callbacks->m_error.c_str();
}

/*
 * The key of SCTP-AUTH: exported by the channel once it is active, computed
 * from the key log as the channel would before - see the file header.
 * esdm_tls_sctp.c asks for it again once the handshake is complete, and
 * compares.
 */
int esdm_tls_backend_export(void *conn, const uint8_t *label,
			    size_t label_len, uint8_t *out, size_t out_len)
{
	auto *c = static_cast<Esdm_Tls_Conn *>(conn);

	try {
		std::string_view l(reinterpret_cast<const char *>(label),
				   label_len);
		int ret;

		if (c->channel->is_active()) {
			Botan::SymmetricKey key =
				c->channel->key_material_export(l, "", out_len);

			if (key.size() != out_len)
				return -EINVAL;
			std::memcpy(out, key.begin(), out_len);
			return 0;
		}

		ret = c->callbacks->export_key(l, out, out_len);
		if (ret)
			c->callbacks->set_error(
				"the master secret is not known to the key log");
		return ret;
	} catch (const std::exception &e) {
		c->callbacks->set_error(e.what());
		return -EINVAL;
	} catch (...) {
		return -EINVAL;
	}
}

} /* extern "C" */
