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
 * tls_emit_data(), which is collected here and pushed to the socket by
 * Esdm_Dtls_Callbacks::flush() as far as the socket takes it - the rest waits
 * for the socket to become writable, see esdm_dtls_backend_flush(). What one
 * call hands over - a record, or a flight of them - goes out as one message of
 * the socket. What the socket has is fed to the channel with received_data(),
 * one message of the socket per call, and the application data of a record
 * comes back through tls_record_received(), which collects it here until
 * esdm_dtls_backend_recv() hands it out, record by record.
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

#include <poll.h>

#include <botan/credentials_manager.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/system_rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>
#include <botan/version.h>

#include "esdm_dtls_backend.h"
#include "esdm_dtls_session.h"
#include "memset_secure.h"

namespace
{

/*
 * DTLS 1.2 exactly, in the secure minimal mode of esdm_dtls_backend.h - a
 * connection lives as long as it does, with the one handshake it started with:
 *
 *  - No ticket is issued: sessions are resumed by ID from the cache of
 *    esdm_dtls_session.h alone, see Esdm_Dtls_Sessions. A client sends an
 *    empty session_ticket extension all the same, which Botan gives no way to
 *    leave out.
 *  - No early data: Botan has none.
 *  - No renegotiation either way: a request for one ends the connection, and
 *    no resumption stands in for one. Botan has no compression and no
 *    heartbeat.
 *  - The extended master secret and, for CBC, Encrypt-then-MAC are required -
 *    see Esdm_Dtls_Callbacks::tls_session_established(), which checks both
 *    whatever the version of Botan.
 *
 * ECDHE with the pre-shared key: preferably
 * TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 of RFC 8442 on brainpoolP512r1;
 * TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 with Encrypt-then-MAC, and secp521r1,
 * with a peer that has neither - the OpenSSL and GnuTLS backends. The link MTU
 * of esdm_dtls_backend.h, as nothing is fragmented on the connection.
 */
class Esdm_Dtls_Policy final : public Botan::TLS::Policy {
    public:
	std::vector<std::string> allowed_ciphers() const override
	{
		return { "AES-256/GCM", "AES-256" };
	}

	std::vector<std::string> allowed_macs() const override
	{
		return { "AEAD", "SHA-384" };
	}

	/*
	 * The suites, GCM first. Botan's own list leaves the CBC suites out of
	 * DTLS: its MAC-then-encrypt decryption keeps a timing channel of Lucky
	 * Thirteen, which DTLS lets an attacker observe as often as it likes.
	 * With Encrypt-then-MAC, the MAC is checked over the ciphertext before
	 * anything is decrypted, and there is no such channel: the CBC suite is
	 * taken with it only - see tls_session_established(). A suite this
	 * build of Botan does not have is left out.
	 */
	std::vector<uint16_t>
	ciphersuite_list(Botan::TLS::Protocol_Version version) const override
	{
		/* ECDHE_PSK_WITH_AES_256_GCM_SHA384, ..._256_CBC_SHA384 */
		static const uint16_t suites[] = { 0xD002, 0xC038 };
		std::vector<uint16_t> list;

		(void)version;

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
	std::shared_ptr<Botan::RandomNumberGenerator> rng;
	std::shared_ptr<Botan::Credentials_Manager> creds;
	std::shared_ptr<const Esdm_Dtls_Policy> policy;
	std::shared_ptr<Botan::TLS::Session_Manager> sessions;
};

/*
 * The sessions, in the cache of esdm_dtls_session.h rather than in a manager
 * of Botan, whose lock a fork() may leave held: a server's under their ID, a
 * client's under the server name of Esdm_Dtls_Sessions::name() - the session
 * ID of the server ahead of the session, which the client offers it. Never a
 * ticket. The lifetime is the cache's, counted from the full handshake: a
 * session a resumption stores again keeps its time.
 */
class Esdm_Dtls_Sessions final : public Botan::TLS::Session_Manager {
    public:
	Esdm_Dtls_Sessions(
		const std::shared_ptr<Botan::RandomNumberGenerator> &rng,
		size_t max)
		: Botan::TLS::Session_Manager(rng)
	{
		if (esdm_dtls_sessions_alloc(max, &m_cache))
			throw std::bad_alloc();
	}

	~Esdm_Dtls_Sessions() override
	{
		esdm_dtls_sessions_free(m_cache);
	}

	Esdm_Dtls_Sessions(const Esdm_Dtls_Sessions &) = delete;
	Esdm_Dtls_Sessions &operator=(const Esdm_Dtls_Sessions &) = delete;

	/*
	 * The server name a client keeps its session under: the socket path
	 * of its server, hashed into a name Botan indicates - which no server
	 * of the ESDM looks at
	 */
	static std::string name(const uint8_t *key, size_t keylen)
	{
		auto hash = Botan::HashFunction::create_or_throw("SHA-256");
		auto digest = hash->process(key, keylen);

		return "esdm-" + Botan::hex_encode(digest.data(), 16, false);
	}

	/* A server: its session of a full handshake */
	std::optional<Botan::TLS::Session_Handle>
	establish(const Botan::TLS::Session &session,
		  const std::optional<Botan::TLS::Session_ID> &id,
		  bool tls12_no_ticket) override
	{
		(void)tls12_no_ticket;
		Botan::TLS::Session_ID sid =
			id ? *id :
			     Botan::TLS::Session_ID(m_rng->random_vec(32));
		auto der = session.DER_encode();

		esdm_dtls_sessions_put(m_cache, sid.data(), sid.size(),
				       der.data(), der.size());
		return Botan::TLS::Session_Handle(sid);
	}

	/* A client: the session of a handshake, kept under its server name */
	void store(const Botan::TLS::Session &session,
		   const Botan::TLS::Session_Handle &handle) override
	{
		const std::string &key = session.server_info().hostname();
		auto id = handle.id();

		if (!id || key.empty() || id->size() > 255)
			return;

		/* A resumption keeps the time of the full handshake */
		auto kept = client_find(key);
		if (kept && kept->handle.id() == id)
			return;

		auto der = session.DER_encode();
		Botan::secure_vector<uint8_t> data;
		data.push_back(static_cast<uint8_t>(id->size()));
		data.insert(data.end(), id->begin(), id->end());
		data.insert(data.end(), der.begin(), der.end());
		esdm_dtls_sessions_put(m_cache, key.data(), key.size(),
				       data.data(), data.size());
	}

	std::optional<Botan::TLS::Session>
	retrieve(const Botan::TLS::Session_Handle &handle,
		 Botan::TLS::Callbacks &callbacks,
		 const Botan::TLS::Policy &policy) override
	{
		(void)callbacks;
		(void)policy;
		return retrieve_one(handle);
	}

	std::vector<Botan::TLS::Session_with_Handle>
	find(const Botan::TLS::Server_Information &info,
	     Botan::TLS::Callbacks &callbacks,
	     const Botan::TLS::Policy &policy) override
	{
		(void)callbacks;
		(void)policy;
		return find_some(info, 1);
	}

	size_t remove(const Botan::TLS::Session_Handle &handle) override
	{
		auto id = handle.id();

		if (!id)
			return 0;
		esdm_dtls_sessions_del(m_cache, id->data(), id->size());
		return 1;
	}

	size_t remove_all() override
	{
		return 0;
	}

    protected:
	std::optional<Botan::TLS::Session>
	retrieve_one(const Botan::TLS::Session_Handle &handle) override
	{
		auto id = handle.id();
		uint8_t *data;
		size_t len;

		if (!id || esdm_dtls_sessions_get(m_cache, id->data(),
						  id->size(), &data, &len))
			return std::nullopt;
		try {
			Botan::TLS::Session session(
				std::span<const uint8_t>(data, len));
			esdm_dtls_sessions_release(data, len);
			return session;
		} catch (...) {
			esdm_dtls_sessions_release(data, len);
			return std::nullopt;
		}
	}

	std::vector<Botan::TLS::Session_with_Handle>
	find_some(const Botan::TLS::Server_Information &info,
		  size_t max_sessions_hint) override
	{
		(void)max_sessions_hint;
		auto kept = client_find(info.hostname());

		if (!kept)
			return {};
		return { std::move(*kept) };
	}

    private:
	std::optional<Botan::TLS::Session_with_Handle>
	client_find(const std::string &key)
	{
		uint8_t *data;
		size_t len;

		if (key.empty() ||
		    esdm_dtls_sessions_get(m_cache, key.data(), key.size(),
					   &data, &len))
			return std::nullopt;
		try {
			size_t idlen = len ? data[0] : 0;

			if (!idlen || len <= 1 + idlen)
				throw std::invalid_argument("session");
			Botan::TLS::Session_ID id(std::vector<uint8_t>(
				data + 1, data + 1 + idlen));
			Botan::TLS::Session session(std::span<const uint8_t>(
				data + 1 + idlen, len - 1 - idlen));
			esdm_dtls_sessions_release(data, len);
			return Botan::TLS::Session_with_Handle{
				std::move(session),
				Botan::TLS::Session_Handle(std::move(id))
			};
		} catch (...) {
			esdm_dtls_sessions_release(data, len);
			return std::nullopt;
		}
	}

	struct esdm_dtls_sessions *m_cache = nullptr;
};
/* The connection as the channel sees it */
class Esdm_Dtls_Callbacks final : public Botan::TLS::Callbacks {
    public:
	explicit Esdm_Dtls_Callbacks(struct esdm_dtls_io *io) : m_io(io)
	{
	}

	/* What was received and not handed out is plaintext */
	~Esdm_Dtls_Callbacks() override
	{
		for (auto &rec : m_records)
			memset_secure(rec.data(), 0, rec.size());
	}

	/* A message of its own */
	void tls_emit_data(std::span<const uint8_t> data) override
	{
		m_msgs.emplace_back(data.begin(), data.end());
	}

	/*
	 * A record of its own - none of the empty ones, which carry nothing,
	 * not even the byte of esdm_dtls.c in front
	 */
	void tls_record_received(uint64_t seq_no,
				 std::span<const uint8_t> data) override
	{
		(void)seq_no;
		if (!data.empty())
			m_records.emplace_back(data.begin(), data.end());
	}

	void tls_alert(Botan::TLS::Alert alert) override
	{
		if (alert.type() == Botan::TLS::Alert::CloseNotify)
			m_peer_closed = true;
		else if (alert.is_fatal())
			m_fatal = true;
	}

	/*
	 * The minimal mode, see Esdm_Dtls_Policy: a session without the
	 * extended master secret (RFC 7627), which binds the master secret to
	 * the handshake it came from, is refused, and so is a CBC suite without
	 * Encrypt-then-MAC, see Esdm_Dtls_Policy::ciphersuite_list(): the
	 * exception ends the handshake with a fatal alert. Every peer of the
	 * ESDM offers and agrees to both, whichever its TLS stack. A resumed
	 * session keeps what its full handshake had, see Esdm_Dtls_Sessions.
	 */
	void tls_session_established(
		const Botan::TLS::Session_Summary &session) override
	{
		if (!session.supports_extended_master_secret())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::InsufficientSecurity,
				"no extended master secret");
		if (session.ciphersuite().cbc_ciphersuite() &&
		    !session.supports_encrypt_then_mac())
			throw Botan::TLS::TLS_Exception(
				Botan::TLS::Alert::InsufficientSecurity,
				"CBC without Encrypt-then-MAC");

		m_cipher = session.ciphersuite().to_string();
	}

	/*
	 * Push out what the channel emitted, as far as the socket takes it -
	 * each message whole. Throws nothing.
	 *
	 * @return 0 when all is out, -EAGAIN if not, a negative errno
	 */
	int flush() noexcept
	{
		while (!m_msgs.empty()) {
			const auto &msg = m_msgs.front();
			int ret = send_msg(msg.data(), msg.size());

			if (ret < 0)
				return ret;
			/* A record cut by the socket */
			if (static_cast<size_t>(ret) != msg.size())
				return -EIO;
			m_msgs.pop_front();
		}
		return 0;
	}

	bool out_pending() const
	{
		return !m_msgs.empty();
	}

	/* Is application data there to be handed out? */
	bool has_data() const
	{
		return !m_records.empty();
	}

	struct esdm_dtls_io *m_io;

	/* The messages to be sent, and the records received */
	std::deque<std::vector<uint8_t> > m_msgs;
	std::deque<std::vector<uint8_t> > m_records;

	bool m_peer_closed = false;
	/*
	 * The channel is dead: a fatal alert of the peer, or one it sent for
	 * what it got
	 */
	bool m_fatal = false;
	std::string m_cipher = "unknown";

    private:
	/* @return the bytes the socket took, -EAGAIN, a negative errno */
	int send_msg(const uint8_t *buf, size_t len) noexcept
	{
		for (;;) {
			ssize_t n = esdm_dtls_io_send(m_io, buf, len);

			if (n >= 0)
				return n > INT32_MAX ? INT32_MAX :
						       static_cast<int>(n);
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return -EAGAIN;
			if (errno == ECONNRESET || errno == EPIPE ||
			    errno == ENOTCONN)
				return -ECONNRESET;
			return -EIO;
		}
	}
};

struct Esdm_Dtls_Conn {
	std::shared_ptr<Esdm_Dtls_Callbacks> callbacks;
	std::unique_ptr<Botan::TLS::Channel> channel;
};

/*
 * The channel took what it was fed: the exception it threw, if any, is the
 * end of the connection, see esdm_dtls_botan_feed().
 *
 * @return 0, or a negative errno
 */
static int esdm_dtls_botan_received(Esdm_Dtls_Conn *c, const uint8_t *buf,
				    size_t len)
{
	auto &cb = *c->callbacks;

	/*
	 * The channel sends the alert of what it throws, and is dead then -
	 * for good: every later call fails the same way.
	 */
	try {
		c->channel->received_data(std::span<const uint8_t>(buf, len));
	} catch (const std::bad_alloc &) {
		cb.m_fatal = true;
		return -ENOMEM;
	} catch (const std::exception &) {
		cb.m_fatal = true;
		return -EPROTO;
	}

	return cb.m_fatal ? -EPROTO : 0;
}

/*
 * Feed the channel what the socket has - one message per call of
 * received_data() -, until the socket has nothing more or the channel has
 * application data.
 *
 * @return 0 if the socket is drained or data is there, -EAGAIN if nothing was
 *	   there to be read, -ECONNRESET at the end of the connection, -EPROTO
 *	   if the channel refused what it got, another negative errno
 */
static int esdm_dtls_botan_feed(Esdm_Dtls_Conn *c)
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
		ssize_t n = esdm_dtls_io_recv(cb.m_io, buf.get(), buflen);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = got ? 0 : -EAGAIN;
				break;
			}
			ret = (errno == ECONNRESET || errno == ENOTCONN) ?
				      -ECONNRESET :
				      -EIO;
			break;
		}
		if (n == 0) {
			ret = -ECONNRESET;
			break;
		}

		got = true;
		ret = esdm_dtls_botan_received(c, buf.get(),
					       static_cast<size_t>(n));
		if (ret)
			break;
	}

	/* Whatever the channel answered - alerts included - goes out */
	if (cb.flush() == -ECONNRESET && !ret)
		ret = -ECONNRESET;

	return ret;
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

		c->rng = std::make_shared<Botan::System_RNG>();
		c->policy = std::make_shared<const Esdm_Dtls_Policy>();
		c->creds = std::make_shared<Esdm_Dtls_Credentials>();
		c->sessions = std::make_shared<Esdm_Dtls_Sessions>(
			c->rng, server ? ESDM_DTLS_SESSIONS_SERVER :
					 ESDM_DTLS_SESSIONS_CLIENT);

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

int esdm_dtls_backend_conn_new(void *ctx, bool server, struct esdm_dtls_io *io,
			       const uint8_t *session_key,
			       size_t session_keylen, void **conn)
{
	auto *c = static_cast<Esdm_Dtls_Ctx *>(ctx);

	try {
		auto d = std::make_unique<Esdm_Dtls_Conn>();

		d->callbacks = std::make_shared<Esdm_Dtls_Callbacks>(io);
		if (server) {
			d->channel = std::make_unique<Botan::TLS::Server>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, true);
		} else {
			/*
			 * The session is kept under the server name of the
			 * socket path. The ClientHello is emitted right away.
			 */
			Botan::TLS::Server_Information info;

			if (session_key && session_keylen)
				info = Botan::TLS::Server_Information(
					Esdm_Dtls_Sessions::name(
						session_key, session_keylen));

			d->channel = std::make_unique<Botan::TLS::Client>(
				d->callbacks, c->sessions, c->creds, c->policy,
				c->rng, info,
				Botan::TLS::Protocol_Version::DTLS_V12);
		}

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

int esdm_dtls_backend_handshake(void *conn, short *want)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

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

			/* Complete once the last flight of ours is out, too */
			if (c->channel->is_handshake_complete())
				return 0;
			if (cb.m_fatal)
				return -EPROTO;
			if (cb.m_peer_closed || c->channel->is_closed())
				return -ECONNRESET;

			ret = esdm_dtls_botan_feed(c);
			if (ret == -EAGAIN) {
				if (cb.out_pending())
					continue;
				*want = POLLIN;
				return -EAGAIN;
			}
			if (ret)
				return ret;
		}
	} catch (...) {
		return -EPROTO;
	}
}

ssize_t esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len,
			       short *want)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

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
			return -EPROTO;
		if (!c->channel->is_active())
			return -ECONNRESET;

		c->channel->send(std::span<const uint8_t>(buf, len));

		/* Taken, whatever of it the socket takes right now */
		ret = cb.flush();
		if (ret && ret != -EAGAIN)
			return ret;

		return static_cast<ssize_t>(len);
	} catch (...) {
		return -EPROTO;
	}
}

int esdm_dtls_backend_flush(void *conn, short *want)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	/* Throws nothing */
	int ret = c->callbacks->flush();

	if (ret == -EAGAIN)
		*want = POLLOUT;
	return ret;
}

ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len,
			       short *want)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	try {
		auto &cb = *c->callbacks;
		size_t n;

		if (!cb.has_data()) {
			int ret;

			if (cb.m_fatal)
				return -EPROTO;
			if (cb.m_peer_closed)
				return 0;

			ret = esdm_dtls_botan_feed(c);
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

		/* A record whole, or none */
		std::vector<uint8_t> rec = std::move(cb.m_records.front());

		cb.m_records.pop_front();
		n = rec.size();
		if (n <= len)
			std::memcpy(buf, rec.data(), n);
		memset_secure(rec.data(), 0, rec.size());
		if (n > len)
			return -EMSGSIZE;
		return static_cast<ssize_t>(n);
	} catch (...) {
		return -EPROTO;
	}
}

bool esdm_dtls_backend_pending(void *conn)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	return c->callbacks->has_data();
}

const char *esdm_dtls_backend_cipher(void *conn)
{
	auto *c = static_cast<Esdm_Dtls_Conn *>(conn);

	return c->callbacks->m_cipher.c_str();
}

} /* extern "C" */
