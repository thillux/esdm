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
 * The backend independent part of esdm_tls.h: the reference counting of the
 * contexts, the revocation policy, what a connection remembers of its peer,
 * and the waiting.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "esdm_sha256.h"
#include "esdm_tls.h"
#include "esdm_tls_backend.h"
#include "helper.h"
#include "leak_check.h"
#include "memset_secure.h"

/* A CRL this close to its nextUpdate is worth a warning */
#define ESDM_TLS_CRL_WARN_SEC (24 * 3600)

/* What was last reported about a CRL, see esdm_tls_ctx_crl_report() */
enum esdm_tls_crl_state {
	esdm_tls_crl_fresh,
	esdm_tls_crl_expiring,
	esdm_tls_crl_expired,
};

struct esdm_tls_ctx {
	void *backend;
	bool server;
	enum esdm_tls_transport transport;
	bool crl_check_all;
	bool crl_allow_expired;
	atomic_uint refcnt;

	/* Serializes the reports of the CRL states */
	pthread_mutex_t report_lock;
	size_t crl_num;
	enum esdm_tls_crl_state *crl_reported;

	/* The next one left behind at the exit, see esdm_tls_exiting() */
	struct esdm_tls_ctx *left_next;
};

struct esdm_tls {
	void *backend;
	struct esdm_tls_ctx *ctx;
	int fd;

	/* What the last operation returning -EAGAIN waits for */
	short want;

	/*
	 * The peer as it authenticated: the chain as the revocation policy
	 * accepted it in the handshake, the rest taken once the handshake
	 * completed. Never changed afterwards - esdm_tls_peer_revoked() reads
	 * it from another thread.
	 */
	bool established;
	uint8_t fingerprint[ESDM_TLS_FINGERPRINT_LEN];
	char subject[ESDM_TLS_TEXT_LEN];
	int64_t not_after;
	struct esdm_tls_der *chain;
	size_t chain_num;

	/* Why the handshake failed, where the backend does not know it */
	char error[ESDM_TLS_TEXT_LEN];

	/* The next one left behind at the exit, see esdm_tls_exiting() */
	struct esdm_tls *left_next;
};

/*
 * The exit of the process, as for the DTLS of the connections - see
 * esdm_dtls_exiting() in esdm_dtls.c: the destructor of a library, or an
 * atexit handler registered before the TLS stack was set up - the teardown of
 * the OpenSSL EGD provider by OPENSSL_cleanup(), for one - may release a
 * connection after the static destructors of the TLS stack ran. Once the
 * process exits, nothing goes into the TLS stack any more: no closing alert is
 * sent, and what is released wipes what this file holds of it and leaves the
 * objects of the TLS stack to the end of the process, reachable on the lists
 * below - and LeakSanitizer is told, see esdm_dtls.c. The atexit handler telling the exit is registered once the first
 * context exists, after the TLS stack set itself up.
 */
static atomic_bool esdm_tls_exit_started = false;
static pthread_once_t esdm_tls_exit_once = PTHREAD_ONCE_INIT;
static _Atomic(struct esdm_tls_ctx *) esdm_tls_ctx_left = NULL;
static _Atomic(struct esdm_tls *) esdm_tls_left = NULL;

static void esdm_tls_at_exit(void)
{
	atomic_store(&esdm_tls_exit_started, true);
}

static void esdm_tls_exit_register(void)
{
	/* Should it fail, the TLS stack is called at the exit as before */
	(void)atexit(esdm_tls_at_exit);
}

static bool esdm_tls_exiting(void)
{
	return atomic_load(&esdm_tls_exit_started);
}

const char *esdm_tls_stack(void)
{
	return esdm_tls_backend_name();
}

/*
 * What TLS 1.3 has of the hybrid key exchange with the TLS stack of the build,
 * see "Algorithms" in esdm_tls.h
 */
static void esdm_tls_pq_report(void)
{
	const char *group = esdm_tls_backend_mlkem_group();

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "TLS: %s, key exchange %s%s\n",
		    esdm_tls_backend_name(),
		    group ? "preferring the hybrid " :
			    "(EC)DHE, no hybrid of ML-KEM",
		    group ? group : "");
}

/* Can the file be read? A clearer error than any TLS stack gives. */
static int esdm_tls_check_file(const char *what, const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int errsv;

	if (fd < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot read the %s %s: %s\n", what, path,
			    strerror(errsv));
		return -errsv;
	}
	close(fd);

	return 0;
}

/*
 * The keys of certificates taken - see "Algorithms" in esdm_tls.h: RSA and
 * ECDSA, conventional signatures BSI TR-02102-1 recommends, as the OIDs of
 * their keys
 */
static const char *const esdm_tls_keys_taken[] = {
	"1.2.840.113549.1.1.1", /* rsaEncryption */
	"1.2.840.113549.1.1.10", /* RSASSA-PSS */
	"1.2.840.10045.2.1", /* id-ecPublicKey */
};

/* Keys refused by name, for the log - any other is refused by its OID */
static const struct {
	const char *oid;
	const char *name;
} esdm_tls_keys_refused[] = {
	{ "2.16.840.1.101.3.4.3.17", "ML-DSA-44" },
	{ "2.16.840.1.101.3.4.3.18", "ML-DSA-65" },
	{ "2.16.840.1.101.3.4.3.19", "ML-DSA-87" },
	{ "1.3.101.112", "Ed25519" },
	{ "1.3.101.113", "Ed448" },
	{ "1.2.840.10040.4.1", "DSA" },
};

/*
 * Is the key of @cert one of esdm_tls_keys_taken? ML-DSA is a post-quantum
 * signature on its own, not in a hybrid with a conventional one, and EdDSA is
 * no signature of BSI TR-02102-1.
 *
 * @return NULL if it is taken - or if the TLS stack cannot tell its algorithm,
 *	   which leaves it to the stack -, the name of its algorithm otherwise
 */
static const char *esdm_tls_key_refused(const struct esdm_tls_cert_info *cert)
{
	size_t i;

	if (!cert->key_oid[0])
		return NULL;
	for (i = 0; i < ARRAY_SIZE(esdm_tls_keys_taken); i++) {
		if (!strcmp(cert->key_oid, esdm_tls_keys_taken[i]))
			return NULL;
	}
	for (i = 0; i < ARRAY_SIZE(esdm_tls_keys_refused); i++) {
		if (!strcmp(cert->key_oid, esdm_tls_keys_refused[i].oid))
			return esdm_tls_keys_refused[i].name;
	}
	return cert->key_oid;
}

/* Largest certificate file read, see esdm_tls_check_keys_file() */
#define ESDM_TLS_MAX_CERT_FILE (4 * 1024 * 1024)

/* The value of a character of base64, -1 for none */
static int esdm_tls_b64(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/*
 * The DER of the base64 of a PEM block from @in to @end into @out, which has
 * room for it: white space skipped, the padding ending it.
 *
 * @return the bytes of DER, -EINVAL for a character of no base64
 */
static ssize_t esdm_tls_pem_der(const char *in, const char *end, uint8_t *out)
{
	uint32_t acc = 0;
	size_t len = 0;
	unsigned int bits = 0;

	for (; in < end && *in != '='; in++) {
		int v;

		if (*in == '\n' || *in == '\r' || *in == ' ' || *in == '\t')
			continue;
		v = esdm_tls_b64(*in);
		if (v < 0)
			return -EINVAL;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[len++] = (uint8_t)(acc >> bits);
		}
	}

	return (ssize_t)len;
}

/*
 * The keys of every certificate in the PEM file @path - the own one and its
 * chain, or the trust anchors -, see esdm_tls_key_refused(): a context is not
 * built with a certificate on another one, whatever the TLS stack would do
 * with it. Run once the TLS stack loaded the file, which tells what else is
 * wrong with it.
 *
 * @return 0, or a negative errno - logged here
 */
static int esdm_tls_check_keys_file(const char *what, const char *path)
{
	static const char begin[] = "-----BEGIN CERTIFICATE-----";
	static const char finish[] = "-----END CERTIFICATE-----";
	struct esdm_tls_der der = { 0 };
	const char *p, *b, *e;
	char *text = NULL;
	struct stat st;
	size_t len = 0;
	ssize_t n;
	int fd, ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto unreadable;
	}
	if (fstat(fd, &st) || st.st_size < 0 ||
	    st.st_size > ESDM_TLS_MAX_CERT_FILE) {
		ret = -EINVAL;
		goto unreadable;
	}
	text = malloc((size_t)st.st_size + 1);
	der.data = malloc((size_t)st.st_size + 1);
	if (!text || !der.data) {
		ret = -ENOMEM;
		goto unreadable;
	}
	while (len < (size_t)st.st_size) {
		n = read(fd, text + len, (size_t)st.st_size - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	text[len] = '\0';

	for (p = text; (b = strstr(p, begin)); p = e + sizeof(finish) - 1) {
		struct esdm_tls_cert_info cert;
		const char *refused;

		b += sizeof(begin) - 1;
		e = strstr(b, finish);
		if (!e)
			break;

		n = esdm_tls_pem_der(b, e, der.data);
		der.len = n > 0 ? (size_t)n : 0;
		if (n <= 0 || esdm_tls_backend_cert_info(&der, &cert)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: a certificate of the %s %s does not parse\n",
				what, path);
			ret = -EINVAL;
			goto out;
		}

		refused = esdm_tls_key_refused(&cert);
		if (refused) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the certificate %s of the %s %s is one of %s, which is not taken - see the algorithms in esdm-egd-net-server(8)\n",
				cert.subject, what, path, refused);
			ret = -EINVAL;
			goto out;
		}
	}
	goto out;

unreadable:
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "TLS: cannot read the %s %s: %s\n", what, path,
		    strerror(-ret));
out:
	if (fd >= 0)
		close(fd);
	free(text);
	free(der.data);
	return ret;
}

int esdm_tls_ctx_alloc(bool server, const struct esdm_tls_config *cfg,
		       struct esdm_tls_ctx **ctx)
{
	struct esdm_tls_ctx *c;
	unsigned int i;
	int ret;

	if (!ctx || !cfg)
		return -EINVAL;
	*ctx = NULL;

	/*
	 * Mutual authentication: the server always presents a certificate and
	 * always verifies the client's against the trust anchors, which every
	 * side needs. A certificate without its key, or the other way round,
	 * is a mistake of the caller.
	 */
	if (!cfg->ca_file || (server && !cfg->cert_file) ||
	    (!cfg->cert_file != !cfg->key_file) ||
	    cfg->crl_files_num > ESDM_TLS_MAX_CRL_FILES ||
	    cfg->transport != ESDM_TLS_TRANSPORT_STREAM)
		return -EINVAL;

	if (cfg->cert_file) {
		ret = esdm_tls_check_file("certificate", cfg->cert_file);
		if (!ret)
			ret = esdm_tls_check_file("key", cfg->key_file);
		if (ret)
			return ret;
	}
	ret = esdm_tls_check_file("trust anchors", cfg->ca_file);
	if (ret)
		return ret;
	for (i = 0; i < cfg->crl_files_num; i++) {
		if (!cfg->crl_files[i])
			return -EINVAL;
		ret = esdm_tls_check_file("CRL", cfg->crl_files[i]);
		if (ret)
			return ret;
	}

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;
	c->server = server;
	c->transport = cfg->transport;
	c->crl_check_all = cfg->crl_check_all;
	c->crl_allow_expired = cfg->crl_allow_expired;
	atomic_init(&c->refcnt, 1);

	ret = esdm_tls_backend_ctx_new(server, cfg->transport, &c->backend);
	if (!ret) {
		ret = esdm_tls_backend_ctx_files(c->backend, server, cfg);
		/* The algorithms of the certificates, see esdm_tls.h */
		if (!ret && cfg->cert_file)
			ret = esdm_tls_check_keys_file("certificate",
						       cfg->cert_file);
		if (!ret)
			ret = esdm_tls_check_keys_file("trust anchors",
						       cfg->ca_file);
		if (ret)
			esdm_tls_backend_ctx_free(c->backend);
	}
	if (ret) {
		free(c);
		return ret;
	}

	/* After the TLS stack set itself up, see esdm_tls_exiting() */
	pthread_once(&esdm_tls_exit_once, esdm_tls_exit_register);

	/*
	 * Files given but nothing in them: a revocation check against no CRL
	 * would refuse every peer - fail closed, see esdm_tls.h -, which is
	 * certainly not what the configuration means.
	 */
	c->crl_num = esdm_tls_backend_crl_count(c->backend);
	if (cfg->crl_files_num && !c->crl_num) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: the CRL files hold no CRL\n");
		esdm_tls_backend_ctx_free(c->backend);
		free(c);
		return -EINVAL;
	}

	/*
	 * The policy takes the CRL of an issuer for the complete list of what
	 * it revoked. A delta CRL lists what was revoked since a base CRL only,
	 * and an issuing distribution point limits a CRL to a part of the
	 * certificates of its issuer: taken for complete, either would have
	 * peers it does not cover pass - or, being the latest one, shadow the
	 * complete CRL of its issuer. They are refused rather than skipped, so
	 * that a configuration relying on one shows.
	 */
	for (i = 0; i < c->crl_num; i++) {
		struct esdm_tls_crl_info info;

		ret = esdm_tls_backend_crl_info(c->backend, i, &info);
		if (!ret && !info.delta && !info.scoped)
			continue;

		if (!ret)
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the CRL of %s is %s, which is not supported - a complete CRL of its issuer is needed\n",
				info.issuer,
				info.delta ? "a delta CRL" :
					     "limited by an issuing distribution point");
		esdm_tls_backend_ctx_free(c->backend);
		free(c);
		return -EINVAL;
	}

	if (c->crl_num) {
		c->crl_reported = calloc(c->crl_num, sizeof(*c->crl_reported));
		if (!c->crl_reported) {
			esdm_tls_backend_ctx_free(c->backend);
			free(c);
			return -ENOMEM;
		}
	}
	pthread_mutex_init(&c->report_lock, NULL);

	if (c->transport == ESDM_TLS_TRANSPORT_STREAM)
		esdm_tls_pq_report();

	*ctx = c;
	return 0;
}

void esdm_tls_ctx_get(struct esdm_tls_ctx *ctx)
{
	if (ctx)
		atomic_fetch_add(&ctx->refcnt, 1);
}

void esdm_tls_ctx_put(struct esdm_tls_ctx *ctx)
{
	if (!ctx || atomic_fetch_sub(&ctx->refcnt, 1) != 1)
		return;

	/* Not into the TLS stack at the exit, see esdm_tls_exiting() */
	if (esdm_tls_exiting()) {
		struct esdm_tls_ctx *head = atomic_load(&esdm_tls_ctx_left);

		esdm_leak_intended(ctx);
		do {
			ctx->left_next = head;
		} while (!atomic_compare_exchange_weak(&esdm_tls_ctx_left,
						       &head, ctx));
		return;
	}

	esdm_tls_backend_ctx_free(ctx->backend);
	pthread_mutex_destroy(&ctx->report_lock);
	free(ctx->crl_reported);
	free(ctx);
}

/* @t as text for the log, in UTC */
static void esdm_tls_time_str(int64_t t, char *buf, size_t len)
{
	time_t tt = (time_t)t;
	struct tm tm;

	/* Beyond a time_t of 32 bits, the number is all there is to tell */
	if ((int64_t)tt != t || !gmtime_r(&tt, &tm) ||
	    !strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", &tm))
		snprintf(buf, len, "%lld", (long long)t);
}

void esdm_tls_ctx_crl_report(struct esdm_tls_ctx *ctx, bool all)
{
	int64_t now = (int64_t)time(NULL);
	size_t i;

	if (!ctx || !ctx->crl_num)
		return;

	pthread_mutex_lock(&ctx->report_lock);

	for (i = 0; i < ctx->crl_num; i++) {
		struct esdm_tls_crl_info info;
		enum esdm_tls_crl_state state = esdm_tls_crl_fresh;
		char when[64];

		if (esdm_tls_backend_crl_info(ctx->backend, i, &info))
			break;

		if (info.next_update) {
			if (now > info.next_update)
				state = esdm_tls_crl_expired;
			else if (info.next_update - now <
				 ESDM_TLS_CRL_WARN_SEC)
				state = esdm_tls_crl_expiring;
		}

		if (state == ctx->crl_reported[i] && !all)
			continue;
		ctx->crl_reported[i] = state;

		esdm_tls_time_str(info.next_update, when, sizeof(when));
		switch (state) {
		case esdm_tls_crl_expired:
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the CRL of %s expired at %s - %s\n",
				info.issuer, when,
				ctx->crl_allow_expired ?
					"still used, as expired CRLs are allowed" :
					"peers it covers are refused until it is renewed");
			break;
		case esdm_tls_crl_expiring:
			esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
				    "TLS: the CRL of %s expires at %s\n",
				    info.issuer, when);
			break;
		case esdm_tls_crl_fresh:
		default:
			break;
		}
	}

	pthread_mutex_unlock(&ctx->report_lock);
}

static void esdm_tls_chain_free(struct esdm_tls_der *chain, size_t num)
{
	size_t i;

	if (!chain)
		return;
	for (i = 0; i < num; i++)
		free(chain[i].data);
	free(chain);
}

/*
 * The revocation policy of esdm_tls.h for @chain as the TLS stack verified it,
 * against the CRLs of @ctx. @revoked_only leaves the missing and the expired
 * CRLs out - for a connection established already.
 *
 * @return the verdict, with the reason in @why if it is no acceptance
 */
static enum esdm_tls_verdict
esdm_tls_check_chain(struct esdm_tls_ctx *ctx, const struct esdm_tls_der *chain,
		     size_t num, bool revoked_only, char *why, size_t whylen)
{
	int64_t now = (int64_t)time(NULL);
	size_t depth;
	int ret;

	if (!ctx->crl_num)
		return esdm_tls_verdict_accepted;

	/*
	 * A peer whose own certificate is a trust anchor has no issuer whose
	 * CRL could cover it - which leaves it uncovered: fail closed.
	 */
	if (num < 2) {
		if (revoked_only)
			return esdm_tls_verdict_accepted;
		snprintf(why, whylen,
			 "the certificate of the peer is a trust anchor, no CRL covers it");
		return esdm_tls_verdict_no_crl;
	}

	/* Up to the trust anchor, which no CRL revokes */
	for (depth = 0; depth + 1 < num; depth++) {
		struct esdm_tls_cert_info cert, issuer;
		struct esdm_tls_crl_result res;
		char when[64];

		ret = esdm_tls_backend_cert_info(&chain[depth], &cert);
		if (!ret)
			ret = esdm_tls_backend_cert_info(&chain[depth + 1],
							 &issuer);
		if (!ret)
			ret = esdm_tls_backend_crl_lookup(ctx->backend,
							  &chain[depth],
							  &chain[depth + 1],
							  &res);
		if (ret) {
			snprintf(why, whylen,
				 "the certificate at depth %zu does not parse",
				 depth);
			return esdm_tls_verdict_bad_chain;
		}

		if (!res.found) {
			if (revoked_only || (depth && !ctx->crl_check_all))
				continue;
			snprintf(why, whylen,
				 "no CRL of %s covers %s (depth %zu)",
				 issuer.subject, cert.subject, depth);
			return esdm_tls_verdict_no_crl;
		}

		if (res.revoked) {
			snprintf(why, whylen,
				 "%s (serial %s) is revoked by the CRL of %s",
				 cert.subject, cert.serial, issuer.subject);
			return esdm_tls_verdict_revoked;
		}

		if (!revoked_only && res.next_update && now > res.next_update) {
			esdm_tls_time_str(res.next_update, when, sizeof(when));
			if (!ctx->crl_allow_expired) {
				snprintf(why, whylen,
					 "the CRL of %s covering %s expired at %s",
					 issuer.subject, cert.subject, when);
				return esdm_tls_verdict_crl_expired;
			}
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ANY,
				"TLS: the CRL of %s covering %s expired at %s - accepted, as expired CRLs are allowed\n",
				issuer.subject, cert.subject, when);
		}
	}

	return esdm_tls_verdict_accepted;
}

/*
 * Is a certificate of @chain - the peer's, a CA's, the trust anchor - on a key
 * esdm_tls_key_refused() refuses? It signed the handshake, or the certificate
 * below it. Checked here for every TLS stack, whatever the stack verifies.
 *
 * @return the verdict, with the reason in @why if it is no acceptance
 */
static enum esdm_tls_verdict
esdm_tls_check_keys(const struct esdm_tls_der *chain, size_t num, char *why,
		    size_t whylen)
{
	size_t depth;

	for (depth = 0; depth < num; depth++) {
		struct esdm_tls_cert_info cert;
		const char *refused;

		if (esdm_tls_backend_cert_info(&chain[depth], &cert)) {
			snprintf(why, whylen,
				 "the certificate at depth %zu does not parse",
				 depth);
			return esdm_tls_verdict_bad_chain;
		}
		refused = esdm_tls_key_refused(&cert);
		if (!refused)
			continue;
		/* A long subject cut off, for the log */
		if (snprintf(why, whylen,
			     "%s (depth %zu) is on %s, which is not taken",
			     cert.subject, depth, refused) < 0)
			why[0] = '\0';
		return esdm_tls_verdict_bad_chain;
	}

	return esdm_tls_verdict_accepted;
}

/*
 * The algorithms of the keys and the revocation policy on the chain of the
 * peer, from the verification of the TLS stack - see esdm_tls_backend_check.
 * The chain they accept is kept for what the connection tells of its peer,
 * and esdm_tls_peer_revoked().
 */
static enum esdm_tls_verdict esdm_tls_check_peer(void *arg,
						 struct esdm_tls_der *chain,
						 size_t num)
{
	struct esdm_tls *tls = arg;
	enum esdm_tls_verdict verdict;

	if (!chain || !num) {
		snprintf(tls->error, sizeof(tls->error),
			 "the peer presented no certificate chain");
		esdm_tls_chain_free(chain, num);
		return esdm_tls_verdict_bad_chain;
	}

	verdict = esdm_tls_check_keys(chain, num, tls->error,
				      sizeof(tls->error));
	if (verdict == esdm_tls_verdict_accepted)
		verdict = esdm_tls_check_chain(tls->ctx, chain, num, false,
					       tls->error, sizeof(tls->error));
	if (verdict != esdm_tls_verdict_accepted) {
		esdm_tls_chain_free(chain, num);
		return verdict;
	}

	/* A TLS stack verifying twice: the last chain is the one */
	esdm_tls_chain_free(tls->chain, tls->chain_num);
	tls->chain = chain;
	tls->chain_num = num;

	return esdm_tls_verdict_accepted;
}

int esdm_tls_alloc(struct esdm_tls_ctx *ctx, int fd, const char *server_name,
		   struct esdm_tls **tls)
{
	struct esdm_tls *t;
	int ret;

	if (!ctx || !tls || fd < 0)
		return -EINVAL;
	*tls = NULL;

	/* A client that does not check the name trusts any server, see header */
	if (!ctx->server && (!server_name || !*server_name))
		return -EINVAL;

	t = calloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;
	t->fd = fd;
	t->want = POLLIN;
	/* The policy of this context checks the peer, see esdm_tls_check_peer() */
	t->ctx = ctx;

	ret = esdm_tls_backend_conn_new(ctx->backend, ctx->server, fd,
					ctx->server ? NULL : server_name,
					esdm_tls_check_peer, t, &t->backend);
	if (ret) {
		free(t);
		return ret;
	}

	esdm_tls_ctx_get(ctx);

	*tls = t;
	return 0;
}

void esdm_tls_free(struct esdm_tls *tls)
{
	if (!tls)
		return;

	/*
	 * Not into the TLS stack at the exit, see esdm_tls_exiting(): what is
	 * this file's is released, the connection of the TLS stack - and with
	 * it the context it uses - is left behind.
	 */
	if (esdm_tls_exiting()) {
		struct esdm_tls *head = atomic_load(&esdm_tls_left);

		esdm_tls_chain_free(tls->chain, tls->chain_num);
		tls->chain = NULL;
		tls->chain_num = 0;

		esdm_leak_intended(tls);
		do {
			tls->left_next = head;
		} while (!atomic_compare_exchange_weak(&esdm_tls_left, &head,
						       tls));
		return;
	}

	esdm_tls_backend_conn_free(tls->backend);
	esdm_tls_ctx_put(tls->ctx);
	esdm_tls_chain_free(tls->chain, tls->chain_num);
	memset_secure(tls, 0, sizeof(*tls));
	free(tls);
}

/*
 * Remember who the peer is, once the handshake completed.
 *
 * @return 0, or -EACCES with the reason in tls->error
 */
static int esdm_tls_established(struct esdm_tls *tls)
{
	struct esdm_tls_cert_info leaf;

	/*
	 * A handshake the policy did not see the chain of cannot complete -
	 * the server requires a certificate of the client, the client one of
	 * the server, and the backend hands either to the policy. Should a TLS
	 * stack still complete one, the connection is no use: fail closed.
	 */
	if (!tls->chain || !tls->chain_num) {
		snprintf(tls->error, sizeof(tls->error),
			 "the peer presented no certificate chain");
		return -EACCES;
	}

	if (esdm_tls_backend_cert_info(&tls->chain[0], &leaf)) {
		snprintf(tls->error, sizeof(tls->error),
			 "the certificate of the peer does not parse");
		return -EACCES;
	}

	esdm_hash(esdm_sha256, tls->chain[0].data, tls->chain[0].len,
		  tls->fingerprint);
	snprintf(tls->subject, sizeof(tls->subject), "%s", leaf.subject);
	tls->not_after = leaf.not_after;
	tls->established = true;

	return 0;
}

int esdm_tls_handshake(struct esdm_tls *tls)
{
	int ret;

	if (!tls)
		return -EINVAL;
	if (tls->established)
		return 0;
	if (tls->error[0])
		return -EACCES;

	ret = esdm_tls_backend_handshake(tls->backend, &tls->want);

	/* The policy refused the peer: whatever the TLS stack made of that */
	if (ret && ret != -EAGAIN && tls->error[0])
		return -EACCES;
	if (ret)
		return ret;

	return esdm_tls_established(tls);
}

ssize_t esdm_tls_send(struct esdm_tls *tls, const void *buf, size_t len)
{
	if (!tls || (!buf && len))
		return -EINVAL;
	if (!tls->established)
		return -ENOTCONN;
	if (!len)
		return 0;

	return esdm_tls_backend_send(tls->backend, buf, len, &tls->want);
}

int esdm_tls_flush(struct esdm_tls *tls)
{
	if (!tls)
		return -EINVAL;
	if (!tls->established)
		return -ENOTCONN;

	return esdm_tls_backend_flush(tls->backend, &tls->want);
}

ssize_t esdm_tls_recv(struct esdm_tls *tls, void *buf, size_t len)
{
	if (!tls || !buf)
		return -EINVAL;
	if (!tls->established)
		return -ENOTCONN;
	if (!len)
		return -EINVAL;

	return esdm_tls_backend_recv(tls->backend, buf, len, &tls->want);
}

short esdm_tls_want(struct esdm_tls *tls)
{
	return tls ? tls->want : 0;
}

bool esdm_tls_pending(struct esdm_tls *tls)
{
	return tls ? esdm_tls_backend_pending(tls->backend) : false;
}

void esdm_tls_close_notify(struct esdm_tls *tls)
{
	/* Nothing is sent at the exit, see esdm_tls_exiting() */
	if (!tls || !tls->established || esdm_tls_exiting())
		return;

	esdm_tls_backend_close_notify(tls->backend);
}

int esdm_tls_peer_fingerprint(struct esdm_tls *tls,
			      uint8_t fp[ESDM_TLS_FINGERPRINT_LEN])
{
	if (!tls || !fp)
		return -EINVAL;
	if (!tls->established)
		return -ENODATA;

	memcpy(fp, tls->fingerprint, ESDM_TLS_FINGERPRINT_LEN);
	return 0;
}

const char *esdm_tls_peer_subject(struct esdm_tls *tls)
{
	return (tls && tls->established) ? tls->subject : "unknown";
}

int64_t esdm_tls_peer_not_after(struct esdm_tls *tls)
{
	return (tls && tls->established) ? tls->not_after : 0;
}

int esdm_tls_peer_revoked(struct esdm_tls *tls, struct esdm_tls_ctx *ctx,
			  char *why, size_t whylen)
{
	char buf[ESDM_TLS_TEXT_LEN];
	enum esdm_tls_verdict verdict;

	if (!tls || !ctx)
		return -EINVAL;
	if (!tls->established)
		return -ENODATA;
	if (!why || !whylen) {
		why = buf;
		whylen = sizeof(buf);
	}
	why[0] = '\0';

	verdict = esdm_tls_check_chain(ctx, tls->chain, tls->chain_num, true,
				       why, whylen);
	if (verdict == esdm_tls_verdict_revoked)
		return 1;

	return verdict == esdm_tls_verdict_bad_chain ? -EINVAL : 0;
}

const char *esdm_tls_cipher(struct esdm_tls *tls)
{
	const char *name = tls ? esdm_tls_backend_cipher(tls->backend) : NULL;

	return name ? name : "none";
}

const char *esdm_tls_group(struct esdm_tls *tls)
{
	const char *name = (tls && tls->established) ?
				   esdm_tls_backend_group(tls->backend) :
				   NULL;

	return name ? name : "none";
}

const char *esdm_tls_mlkem_group(void)
{
	return esdm_tls_backend_mlkem_group();
}

bool esdm_tls_ip6_name(void)
{
	return esdm_tls_backend_ip6_name();
}

const char *esdm_tls_error(struct esdm_tls *tls)
{
	const char *err;

	if (!tls)
		return "none";
	if (tls->error[0])
		return tls->error;

	err = esdm_tls_backend_error(tls->backend);
	return (err && *err) ? err : "none";
}

/* Milliseconds on the monotonic clock. */
static uint64_t esdm_tls_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

int esdm_tls_wait(struct esdm_tls *tls, int timeout_ms)
{
	struct pollfd pfd;
	uint64_t deadline;
	int ret;

	if (!tls)
		return -EINVAL;

	/* Decrypted already, nothing to wait for */
	if (tls->want == POLLIN && esdm_tls_pending(tls))
		return 0;

	pfd.fd = tls->fd;
	pfd.events = tls->want ? tls->want : POLLIN;
	pfd.revents = 0;
	deadline = esdm_tls_now_ms() +
		   (uint64_t)(timeout_ms < 0 ? 0 : timeout_ms);

	/*
	 * A signal does not start the wait over: a periodic one would otherwise
	 * keep a wait for a wedged peer from ever running out.
	 */
	while ((ret = poll(&pfd, 1, timeout_ms)) < 0 && errno == EINTR) {
		if (timeout_ms >= 0) {
			uint64_t now = esdm_tls_now_ms();

			timeout_ms = now >= deadline ?
					     0 :
					     (deadline - now > INT_MAX ?
						      INT_MAX :
						      (int)(deadline - now));
		}
	}

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;

	/*
	 * A hangup or an error of the socket is ready as well: the next
	 * operation on the connection runs into it and reports it.
	 */
	return 0;
}

/* Add what stat(2) tells about @path to the stamp being computed. */
static void esdm_tls_stamp_file(struct esdm_hash_ctx *hash, const char *path)
{
	struct {
		int64_t dev, ino, size, mtime_sec, mtime_nsec, ctime_sec,
			ctime_nsec;
		int32_t err;
	} rec;
	struct stat sb;

	memset(&rec, 0, sizeof(rec));
	if (!path) {
		rec.err = -1;
	} else {
		esdm_hash_update(hash, (const uint8_t *)path,
				 strlen(path) + 1);
		if (stat(path, &sb) < 0) {
			rec.err = errno;
		} else {
			rec.dev = (int64_t)sb.st_dev;
			rec.ino = (int64_t)sb.st_ino;
			rec.size = (int64_t)sb.st_size;
			rec.mtime_sec = (int64_t)sb.st_mtim.tv_sec;
			rec.mtime_nsec = (int64_t)sb.st_mtim.tv_nsec;
			rec.ctime_sec = (int64_t)sb.st_ctim.tv_sec;
			rec.ctime_nsec = (int64_t)sb.st_ctim.tv_nsec;
		}
	}

	esdm_hash_update(hash, (const uint8_t *)&rec, sizeof(rec));
}

void esdm_tls_stamp(const struct esdm_tls_config *cfg,
		    uint8_t stamp[ESDM_TLS_STAMP_LEN])
{
	ESDM_HASH_CTX_ON_STACK(hash, esdm_sha256);
	unsigned int i;

	esdm_hash_init(hash);
	esdm_tls_stamp_file(hash, cfg->cert_file);
	esdm_tls_stamp_file(hash, cfg->key_file);
	esdm_tls_stamp_file(hash, cfg->ca_file);
	for (i = 0; i < cfg->crl_files_num && i < ESDM_TLS_MAX_CRL_FILES; i++)
		esdm_tls_stamp_file(hash, cfg->crl_files[i]);
	esdm_hash_final(hash, stamp);
	esdm_hash_zero(hash);
}
