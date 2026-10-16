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
 * DTLS of esdm_dtls_backend.h by Botan, for crypto_backend=botan.
 *
 * A Botan TLS channel does no I/O of its own: what it has to send it hands to
 * tls_emit_data(), one DTLS record - or a flight of them - per call, which goes
 * out as one message of the socket; what is received is fed to it with
 * received_data(), one message of the socket per call, and the application
 * data of a record comes back through tls_record_received(). The records
 * received are queued here until esdm_dtls_backend_recv() hands them out.
 *
 * No exception crosses into the C code: every entry point catches them and
 * reports an errno.
 */

#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509self.h>

#include <sys/socket.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
#include "memset_secure.h"

namespace
{

/*
 * DTLS 1.2 exactly, ECDHE with ECDSA, AEAD ciphers only, no renegotiation;
 * the link MTU of esdm_dtls_backend.h, as nothing is fragmented on the
 * connection.
 */
class Esdm_Dtls_Policy final : public Botan::TLS::Policy {
    public:
	std::vector<std::string> allowed_ciphers() const override
	{
		return { "AES-256/GCM", "ChaCha20Poly1305", "AES-128/GCM" };
	}

	std::vector<std::string> allowed_macs() const override
	{
		return { "AEAD" };
	}

	std::vector<std::string> allowed_signature_hashes() const override
	{
		return { "SHA-384", "SHA-256" };
	}

	std::vector<std::string> allowed_key_exchange_methods() const override
	{
		return { "ECDH" };
	}

	std::vector<std::string> allowed_signature_methods() const override
	{
		return { "ECDSA" };
	}

	std::vector<Botan::TLS::Group_Params>
	key_exchange_groups() const override
	{
		return { Botan::TLS::Group_Params::X25519,
			 Botan::TLS::Group_Params::SECP256R1 };
	}

	bool allow_tls12() const override
	{
		return false;
	}

	bool allow_tls13() const override
	{
		return false;
	}

	bool allow_dtls12() const override
	{
		return true;
	}

	bool allow_client_initiated_renegotiation() const override
	{
		return false;
	}

	bool allow_server_initiated_renegotiation() const override
	{
		return false;
	}

	size_t dtls_default_mtu() const override
	{
		return ESDM_DTLS_LINK_MTU;
	}

	/*
	 * The cookie exchange protects a server against spoofed addresses -
	 * a client making it send a flight to somebody else. A connected Unix
	 * domain socket has no address to spoof.
	 */
	bool dtls_server_require_cookie_exchange() const override
	{
		return false;
	}
};

/*
 * The ephemeral key and certificate of a server; a client has none and trusts
 * nobody - unauthenticated, see esdm_dtls.h.
 */
class Esdm_Dtls_Credentials final : public Botan::Credentials_Manager {
    public:
	explicit Esdm_Dtls_Credentials(Botan::RandomNumberGenerator &rng)
	{
		auto group = Botan::EC_Group::from_name("secp256r1");
		Botan::X509_Cert_Options opts("esdm");
		auto now = std::chrono::system_clock::now();

		m_key = std::make_shared<Botan::ECDSA_PrivateKey>(rng, group);
		opts.start = Botan::X509_Time(now - std::chrono::hours(1));
		opts.end =
			Botan::X509_Time(now + std::chrono::hours(24 * 3650));
		m_cert = std::make_unique<Botan::X509_Certificate>(
			Botan::X509::create_self_signed_cert(opts, *m_key,
							     "SHA-256", rng));
	}

	Esdm_Dtls_Credentials() = default;

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

		if (!m_cert || type != "tls-server")
			return {};
		for (const auto &kt : cert_key_types) {
			if (kt == "ECDSA")
				return { *m_cert };
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

		if (m_cert && cert == *m_cert)
			return m_key;
		return nullptr;
	}

    private:
	std::shared_ptr<Botan::Private_Key> m_key;
	std::unique_ptr<Botan::X509_Certificate> m_cert;
};

struct Esdm_Dtls_Ctx {
	bool server;
	std::shared_ptr<Botan::RandomNumberGenerator> rng;
	std::shared_ptr<Esdm_Dtls_Credentials> creds;
	std::shared_ptr<const Esdm_Dtls_Policy> policy;
	std::shared_ptr<Botan::TLS::Session_Manager_Noop> sessions;
};

/* The connection as the channel sees it */
class Esdm_Dtls_Callbacks final : public Botan::TLS::Callbacks {
    public:
	explicit Esdm_Dtls_Callbacks(int fd) : m_fd(fd)
	{
	}

	/* What was received and not handed out is plaintext */
	~Esdm_Dtls_Callbacks() override
	{
		for (auto &rec : m_records)
			memset_secure(rec.data(), 0, rec.size());
	}

	void tls_emit_data(std::span<const uint8_t> data) override
	{
		ssize_t n = send(m_fd, data.data(), data.size(),
				 MSG_DONTWAIT | MSG_NOSIGNAL);

		/* Told to the caller once the channel returns */
		if (n != static_cast<ssize_t>(data.size()))
			m_send_error = n < 0 && (errno == EAGAIN ||
						 errno == EWOULDBLOCK) ?
					       -EAGAIN :
					       -EIO;
	}

	void tls_record_received(uint64_t seq_no,
				 std::span<const uint8_t> data) override
	{
		(void)seq_no;
		m_records.emplace_back(data.begin(), data.end());
	}

	void tls_alert(Botan::TLS::Alert alert) override
	{
		if (alert.is_fatal() ||
		    alert.type() == Botan::TLS::Alert::CloseNotify)
			m_closed = true;
	}

	void tls_session_established(
		const Botan::TLS::Session_Summary &session) override
	{
		m_cipher = session.ciphersuite().to_string();
	}

	/* Unauthenticated, see esdm_dtls.h: any certificate is fine */
	void tls_verify_cert_chain(
		const std::vector<Botan::X509_Certificate> &cert_chain,
		const std::vector<std::optional<Botan::OCSP::Response> >
			&ocsp_responses,
		const std::vector<Botan::Certificate_Store *> &trusted_roots,
		Botan::Usage_Type usage, std::string_view hostname,
		const Botan::TLS::Policy &policy) override
	{
		(void)cert_chain;
		(void)ocsp_responses;
		(void)trusted_roots;
		(void)usage;
		(void)hostname;
		(void)policy;
	}

	int take_send_error()
	{
		int ret = m_send_error;

		m_send_error = 0;
		return ret;
	}

	int m_fd;
	int m_send_error = 0;
	bool m_closed = false;
	std::deque<std::vector<uint8_t> > m_records;
	std::string m_cipher = "unknown";
};

struct Esdm_Dtls_Conn {
	std::shared_ptr<Esdm_Dtls_Callbacks> callbacks;
	std::unique_ptr<Botan::TLS::Channel> channel;
};

/*
 * Feed the channel what the socket has: one message per call of
 * received_data(), until the socket has nothing more.
 *
 * @return 0 if the socket is drained, -ECONNRESET if the peer is gone,
 *	   -EPROTO if the channel refused what it got, another negative errno
 */
static int esdm_dtls_botan_feed(Esdm_Dtls_Conn *c)
{
	uint8_t buf[ESDM_DTLS_LINK_MTU + 512];

	for (;;) {
		ssize_t n = recv(c->callbacks->m_fd, buf, sizeof(buf),
				 MSG_DONTWAIT);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR)
				return 0;
			return -errno;
		}
		if (n == 0)
			return -ECONNRESET;

		c->channel->received_data(
			std::span<const uint8_t>(buf, static_cast<size_t>(n)));
		if (c->callbacks->m_closed || c->channel->is_closed())
			return -ECONNRESET;
		if (!c->callbacks->m_records.empty())
			return 0;
	}
}

} // namespace

/******************************************************************************
 * esdm_dtls_backend.h
 ******************************************************************************/

extern "C" {

const char *esdm_dtls_backend_name(void)
{
	return "Botan";
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	try {
		auto c = std::make_unique<Esdm_Dtls_Ctx>();

		c->server = server;
		c->rng = std::make_shared<Botan::System_RNG>();
		c->creds = server ? std::make_shared<Esdm_Dtls_Credentials>(
					    *c->rng) :
				    std::make_shared<Esdm_Dtls_Credentials>();
		c->policy = std::make_shared<const Esdm_Dtls_Policy>();
		c->sessions =
			std::make_shared<Botan::TLS::Session_Manager_Noop>();

		*ctx = c.release();
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

void esdm_dtls_backend_ctx_free(void *ctx)
{
	delete static_cast<Esdm_Dtls_Ctx *>(ctx);
}

int esdm_dtls_backend_conn_new(void *ctx, bool server, int fd, void **conn)
{
	auto *c = static_cast<Esdm_Dtls_Ctx *>(ctx);

	try {
		auto d = std::make_unique<Esdm_Dtls_Conn>();

		d->callbacks = std::make_shared<Esdm_Dtls_Callbacks>(fd);
		if (server)
			d->channel = std::make_unique<Botan::TLS::Server>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, true);
		else
			/* Sends the ClientHello right away */
			d->channel = std::make_unique<Botan::TLS::Client>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, Botan::TLS::Server_Information(),
				Botan::TLS::Protocol_Version::DTLS_V12);

		if (d->callbacks->take_send_error())
			return -EIO;

		*conn = d.release();
		return 0;
	} catch (...) {
		return -ENOMEM;
	}
}

void esdm_dtls_backend_conn_free(void *conn)
{
	delete static_cast<Esdm_Dtls_Conn *>(conn);
}

int esdm_dtls_backend_handshake(void *conn)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	try {
		int ret;

		if (c->channel->is_active())
			return 0;

		ret = esdm_dtls_botan_feed(c);
		if (!ret)
			ret = c->callbacks->take_send_error();
		if (ret)
			return ret;

		return c->channel->is_active() ? 0 : -EAGAIN;
	} catch (...) {
		return -EPROTO;
	}
}

int esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	try {
		if (!c->channel->is_active())
			return -EPROTO;

		c->channel->send(std::span<const uint8_t>(buf, len));
		return c->callbacks->take_send_error();
	} catch (...) {
		return -EPROTO;
	}
}

ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	try {
		auto &records = c->callbacks->m_records;

		if (records.empty()) {
			int ret = esdm_dtls_botan_feed(c);

			if (!ret)
				ret = c->callbacks->take_send_error();
			if (ret)
				return ret;
			if (records.empty())
				return -EAGAIN;
		}

		std::vector<uint8_t> rec = std::move(records.front());
		size_t n = rec.size() < len ? rec.size() : len;

		records.pop_front();
		std::memcpy(buf, rec.data(), n);
		memset_secure(rec.data(), 0, rec.size());

		/* A record larger than @len: its size tells the caller */
		return static_cast<ssize_t>(rec.size() > len ? len : n);
	} catch (...) {
		return -EPROTO;
	}
}

bool esdm_dtls_backend_pending(void *conn)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	return !c->callbacks->m_records.empty();
}

const char *esdm_dtls_backend_cipher(void *conn)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	return c->callbacks->m_cipher.c_str();
}

} /* extern "C" */
