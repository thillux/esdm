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

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <botan/credentials_manager.h>
#include <botan/secmem.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/version.h>

#include <sys/socket.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
#include "memset_secure.h"

namespace
{

/*
 * DTLS 1.2 exactly: TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 of RFC 8442 on
 * brainpoolP512r1, or on secp521r1 with a peer that does not offer it - the
 * OpenSSL and GnuTLS backends, which offer secp521r1 only; no renegotiation;
 * the link MTU of esdm_dtls_backend.h, as nothing is fragmented on the
 * connection.
 */
class Esdm_Dtls_Policy final : public Botan::TLS::Policy {
    public:
	std::vector<std::string> allowed_ciphers() const override
	{
		return { "AES-256/GCM" };
	}

	std::vector<std::string> allowed_macs() const override
	{
		return { "AEAD" };
	}

	std::vector<std::string> allowed_key_exchange_methods() const override
	{
		return { "ECDHE_PSK" };
	}

	/* A PSK suite signs nothing: the key exchange authenticates it */
	std::vector<std::string> allowed_signature_methods() const override
	{
		return { "IMPLICIT" };
	}

	std::vector<Botan::TLS::Group_Params>
	key_exchange_groups() const override
	{
		return { Botan::TLS::Group_Params::BRAINPOOL512R1,
			 Botan::TLS::Group_Params::SECP521R1 };
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
	 * domain socket has no address to spoof. Botan requires it from 3.13
	 * on; before, the empty Credentials_Manager::dtls_cookie_secret() of
	 * Esdm_Dtls_Credentials turns it off.
	 */
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3, 13, 0)
	bool dtls_server_require_cookie_exchange() const override
	{
		return false;
	}
#endif
};

/*
 * The pre-shared key of either side and its identity, see
 * esdm_dtls_backend.h; no certificate. A server knows no other identity, and
 * refuses a client with another one.
 */
class Esdm_Dtls_Credentials final : public Botan::Credentials_Manager {
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
	 * cookies, see Esdm_Dtls_Policy. A PSK of TLS 1.2 has no PRF of its
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
		if (n == static_cast<ssize_t>(data.size()))
			return;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			m_send_error = -EAGAIN;
		else if (n < 0 && (errno == ECONNRESET || errno == EPIPE ||
				   errno == ENOTCONN))
			m_send_error = -ECONNRESET;
		else
			m_send_error = -EIO;
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
	/*
	 * On the heap, see esdm_dtls.c - and left uninitialized: it receives
	 * the records as they are on the wire, which are of no secrecy, so there
	 * is nothing to wipe afterwards either. Zeroing 17 KiB for every call,
	 * also for one that finds the socket empty, was a share of every
	 * request.
	 */
	const size_t buflen = ESDM_DTLS_LINK_MTU + 512;
	std::unique_ptr<uint8_t[]> buf(new uint8_t[buflen]);

	for (;;) {
		ssize_t n = recv(c->callbacks->m_fd, buf.get(), buflen,
				 MSG_DONTWAIT);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR)
				return 0;
			return -errno;
		}
		if (n == 0)
			return -ECONNRESET;

		c->channel->received_data(std::span<const uint8_t>(
			buf.get(), static_cast<size_t>(n)));
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
		/*
		 * The allocator of Botan's secure memory, which a context of
		 * a client does not need yet: set up now, its static
		 * destructor runs after the exit handler esdm_dtls.c registers
		 * next - see esdm_dtls_exiting() there.
		 */
		Botan::secure_vector<uint8_t> allocator(1);
		auto c = std::make_unique<Esdm_Dtls_Ctx>();

		c->server = server;
		c->rng = std::make_shared<Botan::System_RNG>();
		c->creds = std::make_shared<Esdm_Dtls_Credentials>();
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
