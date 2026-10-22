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
 * External entropy sources for the ESDM - see libesdm_es_ext(3).
 *
 * An external entropy source is noise source code that is not part of the
 * ESDM. It is served to the ESDM by a provider: a process of its own, which the
 * ESDM reads from over a Unix domain socket (esdm-server --es_ext_socket PATH,
 * meson option es_ext_socket_path). The ESDM loads no code of a source into
 * its own process.
 *
 * A provider is written against struct esdm_es_ext_plugin below - the
 * callbacks of the source - and served with libesdm_es_ext: a program whose
 * main() hands its callbacks to esdm_es_ext_provider_main() takes the command
 * line of a provider and serves them, and esdm_es_ext_server_*() serve them
 * from a program of its own making. The protocol is documented below for
 * providers written without the library.
 *
 * The ESDM credits a block with the entropy the source claims for it, but at
 * most with what its configured entropy rate allows, and with nothing for a
 * block whose claim exceeds its size.
 */

#ifndef _ESDM_ES_EXT_H
#define _ESDM_ES_EXT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * The callbacks of a source
 ******************************************************************************/

/*
 * Version of struct esdm_es_ext_plugin a source is written against. A later
 * version may add members at the end, and a source of an earlier one, whose
 * struct ends before them, is served all the same.
 */
#define ESDM_ES_EXT_PLUGIN_VERSION 1

/* The highest entropy rate a source may declare: bits per 256 bits of data */
#define ESDM_ES_EXT_ENTROPY_RATE_MAX 256

/*
 * The largest status @status_json may report: bytes of JSON text, the
 * terminating NUL not counted
 */
#define ESDM_ES_EXT_STATUS_MAX 512

/*
 * The largest status a provider answers STATUS with: bytes of JSON text. The
 * provider server of libesdm_es_ext wraps the status its source reports, of up
 * to ESDM_ES_EXT_STATUS_MAX bytes, into one of its own - see STATUS below.
 */
#define ESDM_ES_EXT_PROTO_STATUS_MAX 1024

/*
 * The longest name a source may declare: bytes of UTF-8, the terminating NUL
 * not counted - see @name of struct esdm_es_ext_plugin
 */
#define ESDM_ES_EXT_NAME_MAX 32

/**
 * struct esdm_es_ext_plugin - the callbacks of an external entropy source
 *
 * What a provider serves: the noise source behind it, handed to
 * esdm_es_ext_provider_main() or esdm_es_ext_server_alloc(), e.g.
 *
 *	static const struct esdm_es_ext_plugin my_source = {
 *		.version = ESDM_ES_EXT_PLUGIN_VERSION,
 *		.name = "my-noise-source",
 *		.get_entropy = my_get_entropy,
 *	};
 *
 *	int main(int argc, char *argv[])
 *	{
 *		return esdm_es_ext_provider_main(&my_source, argc, argv);
 *	}
 *
 * The struct keeps the name it had when a source could be loaded into the
 * ESDM as a plugin library: providers are compiled against it.
 *
 * The callbacks are never called concurrently: the provider server of
 * libesdm_es_ext serializes them. They all run in the process of the
 * provider, @init with the privileges the provider was started with.
 *
 * @version: ESDM_ES_EXT_PLUGIN_VERSION
 * @name: Name of the source: the ESDM shows the source under it in its
 *	  status, and in its log, in place of the name of the entropy source it
 *	  reads the provider with - "ExternalSocket", or "ExternalSocket0",
 *	  "ExternalSocket1" and so on in an ESDM with several - which the
 *	  status keeps as the "instance" of the source. 1 to
 *	  ESDM_ES_EXT_NAME_MAX bytes of UTF-8 without control characters,
 *	  terminated by a NUL; a name that is none of that, or the name of
 *	  another entropy source of the ESDM, is refused, and the source shown
 *	  under its instance name. Two sources may declare the same name. May
 *	  be NULL. The provider declares it in its answer to INFO, see below.
 * @init: Set the source up and return its context in *ctx, which is handed to
 *	  the other callbacks. Returns 0 or a negative errno, in which case the
 *	  source is not served. May be NULL.
 * @fini: Tear the source down. May be NULL.
 * @get_entropy: Fill all @buflen bytes of @buf with data of the noise source
 *		 and set *@entropy_bits to the entropy they hold, at most
 *		 @buflen * 8. Returns 0, or a negative errno if the source could
 *		 not deliver - the data is discarded then. Must not block for
 *		 long: it runs while a DRNG of the ESDM waits for its seed.
 * @selftest: Check that the source still works, without consuming the data
 *	      the ESDM is handed. Returns 0 or a negative errno. Run before the
 *	      ESDM credits the source for the first time - at start up before
 *	      it seeds its DRNGs -, on every new connection of the ESDM to the
 *	      provider - one that was not there at start up, or one restarted -
 *	      before the provider is credited, and on the interval of the ESDM
 *	      self tests. May be NULL.
 * @status_json: Write the status of the source - whatever helps whoever looks
 *		 at the ESDM status, e.g. the device read or the health of the
 *		 noise source - into @buf of @buflen bytes as one JSON object,
 *		 terminated by a NUL: { "device": "/dev/hwrng", "reads": 42 }.
 *		 @buflen leaves room for ESDM_ES_EXT_STATUS_MAX bytes of text.
 *		 Returns 0, -EMSGSIZE if the status does not fit, or another
 *		 negative errno. The ESDM shows it as the "plugin" member of the
 *		 status of the provider, the "provider" member of the state of
 *		 the source - see STATUS below -, and leaves out a status that
 *		 is no JSON object. Asked for when the ESDM status is, at most
 *		 every 5 seconds, so it must not block for long. May be NULL.
 * @entropy_rate: The entropy rate the source declares for its data, bits of
 *		  entropy per 256 bits of data, 0 to
 *		  ESDM_ES_EXT_ENTROPY_RATE_MAX - a rate beyond is taken as
 *		  that. Called once after @init, so that the source can decide
 *		  from the hardware it found. The provider declares it in its
 *		  answer to INFO, and the ESDM credits a block of the source
 *		  with what @get_entropy claims for it, at most with this rate -
 *		  unless a rate is configured for the source in the ESDM, which
 *		  takes precedence. Without it, the provider declares none, and
 *		  the ESDM credits it at 0 unless configured otherwise. May be
 *		  NULL.
 */
struct esdm_es_ext_plugin {
	uint32_t version;
	const char *name;
	int (*init)(void **ctx);
	void (*fini)(void *ctx);
	int (*get_entropy)(void *ctx, uint8_t *buf, size_t buflen,
			   uint32_t *entropy_bits);
	int (*selftest)(void *ctx);
	int (*status_json)(void *ctx, char *buf, size_t buflen);
	uint32_t (*entropy_rate)(void *ctx);
};

/******************************************************************************
 * Socket protocol
 *
 * The ESDM connects to the provider's SOCK_SEQPACKET Unix domain socket and
 * sends requests on the connection, one at a time; the provider answers each
 * with exactly one response. Requests and responses are one message each. All
 * integers are little endian.
 *
 *	esdm-server                                  provider process
 *	+--------------------------+                 +-----------------------+
 *	| ExternalSocket n         |  SOCK_SEQPACKET | esdm-es-pkcs11, a     |
 *	| connects, as the user it |---------------->| program of esdm_es_   |
 *	| dropped its privileges to|  Unix socket    | ext_provider_main(),  |
 *	| (nobody); checks the uid |                 | or one of your own;   |
 *	| of the provider          |                 | listens, checks the   |
 *	|                          |                 | uid of the ESDM       |
 *	+--------------------------+                 +-----------------------+
 *
 * A connection, from the ESDM's side:
 *
 *	ESDM                                                        provider
 *	  |-- connect(2) ------------------------------------------------->|
 *	  |                                                                |
 *	  |-- STARTDTLS, length 0 ---------------------------------------->|
 *	  |<-------------------------- status 0, or -EOPNOTSUPP: no DTLS --|
 *	  |                                                                |
 *	  |== DTLS 1.2 handshake, the ESDM the client ====================>|
 *	  |<======================================== only after status 0 ==|
 *	  |                                                                |
 *	  |-- INFO, length 0 --------------------------------------------->|
 *	  |<------------------------------- status 0, entropy_rate, name --|
 *	  |                                                                |
 *	  |-- SELFTEST, length 0 ----------------------------------------->|
 *	  |<----------------------------------------------------- status --|
 *	  |                                                                |
 *	  |-- GET_ENTROPY, length ---------------------------------------->|
 *	  |<------------------------- status, entropy_bits, length bytes --|
 *	  |                                                                |
 *	  |-- STATUS, length --------------------------------------------->|
 *	  |<------------------------------- status, JSON of up to length --|
 *	  :                                                                :
 *
 * STARTDTLS only by an ESDM built with DTLS, and only first; INFO once per
 * connection, before anything else but STARTDTLS; SELFTEST before the ESDM
 * credits the source for the first time and on the interval of its self
 * tests; GET_ENTROPY whenever the ESDM collects a seed; STATUS when the
 * status of the ESDM is asked for. One request at a time, each answered
 * before the next is sent.
 *
 * Request, ESDM_ES_EXT_PROTO_REQ_LEN (12) bytes:
 *
 *	0               4       6       8               12
 *	+---------------+-------+-------+---------------+
 *	|     magic     |version| type  |    length     |
 *	|  45 53 45 58  | 01 00 |       |               |
 *	|    "ESEX"     |       |       |               |
 *	+---------------+-------+-------+---------------+
 *
 *	u32 magic		ESDM_ES_EXT_PROTO_MAGIC
 *	u16 version		ESDM_ES_EXT_PROTO_VERSION
 *	u16 type		ESDM_ES_EXT_PROTO_GET_ENTROPY,
 *				ESDM_ES_EXT_PROTO_SELFTEST,
 *				ESDM_ES_EXT_PROTO_STARTDTLS,
 *				ESDM_ES_EXT_PROTO_STATUS or
 *				ESDM_ES_EXT_PROTO_INFO
 *	u32 length		bytes asked for, 1 to ESDM_ES_EXT_PROTO_MAX_DATA
 *				for GET_ENTROPY; the largest status taken, 1 to
 *				ESDM_ES_EXT_PROTO_STATUS_MAX, for STATUS; 0
 *				otherwise
 *
 * Response, ESDM_ES_EXT_PROTO_RSP_LEN (16) bytes followed by the data:
 *
 *	0               4       6       8               12              16
 *	+---------------+-------+-------+---------------+---------------+- - -
 *	|     magic     |version| type  |    status     | entropy_bits  | data
 *	|    "ESEX"     |   1   |       |  0 or -errno  |               |
 *	+---------------+-------+-------+---------------+---------------+- - -
 *
 *	u32 magic		ESDM_ES_EXT_PROTO_MAGIC
 *	u16 version		ESDM_ES_EXT_PROTO_VERSION
 *	u16 type		type of the request answered
 *	s32 status		0, or a negative errno
 *	u32 entropy_bits	entropy of the data, at most 8 * length for a
 *				GET_ENTROPY, 0 otherwise
 *	u8  data[]		exactly length bytes for a GET_ENTROPY answered
 *				with status 0; the status, 1 to length bytes of
 *				JSON text without a NUL, for a STATUS answered
 *				with status 0; what the provider declares of
 *				itself, 4 to 4 + ESDM_ES_EXT_NAME_MAX bytes, for
 *				an INFO answered with status 0, see below;
 *				nothing otherwise
 *
 * A response that breaks any of this is discarded and the connection closed.
 * A provider closes a connection on a request that breaks it - including one
 * of a type it does not know.
 *
 * STATUS: the status of the source - one JSON object of up to the length
 * asked for, at most ESDM_ES_EXT_PROTO_STATUS_MAX bytes, nested no deeper than
 * 9 levels, which the ESDM shows as the "provider" member of the source in its
 * own status. A provider without one answers -EOPNOTSUPP, one whose status does
 * not fit into the length -EMSGSIZE. The provider server of libesdm_es_ext
 * answers with an object of its own:
 *	{ "server": { ... }, "plugin": ... }
 * "plugin" being the status the @status_json callback of its source reports -
 * null for a source without one, one that fails, or one that is no JSON object
 * of up to ESDM_ES_EXT_STATUS_MAX bytes, nested no deeper than 8 levels, and
 * for one that does not fit into the length next to the fields of the server -
 * and "server" what the server knows itself: its "version", the "plugin_api"
 * version of the struct esdm_es_ext_plugin of its source, the "name" and
 * "entropy_rate" it declares in its answer to INFO (null for none), whether the
 * "dtls" of the connection asking is on, the "clients" connected and the
 * "client_slots" there are, the "requests" served, the "selftest" verdict of
 * the source ("passed", "failed" or "none" before the first one) and its
 * "uptime_seconds". A provider written without the library answers with an
 * object of its own making. The ESDM asks for it when its own status is asked
 * for, at most every 5 seconds - showing the last one in between - and not
 * while a request is in progress, going without it then. A provider older than
 * STATUS closes the connection on it: the next request of the ESDM connects
 * again at once, and the ESDM reports no status of the provider until the
 * connection is lost the next time. The ESDM waits for the answer a quarter of
 * the timeout of a request at the most, as the source is held meanwhile; a
 * provider answering later keeps its connection - its answer comes in before
 * the one to the next request, and the ESDM takes it off the connection then -
 * and is not asked for its status for a minute.
 *
 * INFO: what the provider declares of itself, which the ESDM asks for once
 * per connection - right after STARTDTLS and the DTLS handshake, inside the
 * DTLS session where there is one, before any other request. The request has
 * length 0. A provider answers it with status 0 and the data
 *
 *	16              20                                    20 + n
 *	+---------------+-------------------------------------+
 *	| entropy_rate  | name, n = 0 to ESDM_ES_EXT_NAME_MAX |
 *	+---------------+-------------------------------------+
 *
 *	u32 entropy_rate	the entropy rate the provider declares for its
 *				data, bits per 256 bits of data, 0 to
 *				ESDM_ES_EXT_ENTROPY_RATE_MAX - one beyond is
 *				taken as that; ESDM_ES_EXT_PROTO_RATE_NONE
 *				(0xffffffff) for none
 *	u8  name[]		0 to ESDM_ES_EXT_NAME_MAX bytes: the name of the
 *				source, UTF-8 without control characters and
 *				without a NUL - none for a provider without a
 *				name
 * or with a negative errno and no data, which declares nothing. The ESDM shows
 * the source under the name, as @name of struct esdm_es_ext_plugin describes:
 * a name that is not valid is not taken, and the source shown under its
 * instance name. It credits the provider at the rate it declares, unless a
 * rate is configured for the source, and at 0 if the provider declares none:
 * accepting the user a provider runs as means trusting the rate it declares -
 * an operator who does not want that configures the rate of the source. The
 * provider server of libesdm_es_ext answers with the @name and the
 * @entropy_rate of its source, or the ones set with
 * esdm_es_ext_server_set_name() and esdm_es_ext_server_set_entropy_rate() -
 * the --name and --entropy_rate options of a provider program. A provider
 * older than INFO closes the connection on it: the ESDM connects again at once
 * and does not ask on that connection, so the provider keeps working without
 * a name and a rate. Both are asked for on every connection: a provider
 * restarted may declare others.
 *
 * DTLS: an ESDM built with DTLS (meson option dtls) sends STARTDTLS as its
 * first request. A provider answering it with status 0 expects a DTLS 1.2
 * handshake on the connection next, the ESDM being the client: every DTLS
 * record, handshake records included, is one message. All later requests and
 * responses are DTLS application data, each one carried by records with one
 * byte in front - 1 if more parts of it follow, 0 for the last one, see
 * esdm_dtls.h - and STARTDTLS is not sent again:
 *
 *	one message, cut into parts of at most ESDM_DTLS_PART_SIZE bytes
 *	+-----------------------------------------------------------+
 *	|                 request or response                       |
 *	+-----------------------------------------------------------+
 *	each part one DTLS record, one SOCK_SEQPACKET message each
 *	+---+------------------------------+  +---+------------------+
 *	| 1 | part 1                       |  | 0 | last part        |
 *	+---+------------------------------+  +---+------------------+
 *
 * A
 * provider that cannot do DTLS answers -EOPNOTSUPP, and the connection goes on
 * unencrypted. A provider that does not know STARTDTLS closes the connection,
 * and the ESDM connects again without asking - so do a failed handshake.
 *
 * The DTLS is opportunistic and unauthenticated: an ephemeral ECDH key
 * exchange keyed with a pre-shared key that is a constant of the ESDM and no
 * secret, without certificates - ECDHE-PSK with AES-256-GCM on
 * brainpoolP512r1 between two builds with Botan, with AES-256-CBC and
 * Encrypt-then-MAC on secp521r1 otherwise. What the ESDM trusts the provider
 * for are the credentials of the process on the other end of the Unix domain
 * socket. The DTLS keeps the data from being read off the channel by whoever
 * can observe it.
 ******************************************************************************/

#define ESDM_ES_EXT_PROTO_MAGIC 0x58455345 /* "ESEX" in memory */
#define ESDM_ES_EXT_PROTO_VERSION 1
#define ESDM_ES_EXT_PROTO_GET_ENTROPY 1
#define ESDM_ES_EXT_PROTO_SELFTEST 2
#define ESDM_ES_EXT_PROTO_STARTDTLS 3
#define ESDM_ES_EXT_PROTO_STATUS 4
#define ESDM_ES_EXT_PROTO_INFO 5
#define ESDM_ES_EXT_PROTO_RATE_NONE 0xffffffffU
#define ESDM_ES_EXT_PROTO_MAX_DATA 512
#define ESDM_ES_EXT_PROTO_REQ_LEN 12
#define ESDM_ES_EXT_PROTO_RSP_LEN 16

/******************************************************************************
 * Provider server - libesdm_es_ext
 ******************************************************************************/

struct esdm_es_ext_server;

/**
 * @brief Serve an external entropy source on a Unix domain socket
 *
 * Creates the socket file @socket_path with the access mode @mode and calls the
 * @init callback of @plugin. A program serving one source does all of this,
 * and what follows, with esdm_es_ext_provider_main() - see below. An existing socket file at @socket_path is
 * replaced, any other file is not. The ESDM connects with its privileges
 * dropped (user nobody by default), so the socket has to be connectable for
 * that user - see esdm-server(8) on how the ESDM checks the provider in turn.
 *
 * @param [in] plugin The callbacks of the entropy source to serve, version 1
 *		      to ESDM_ES_EXT_PLUGIN_VERSION with a @get_entropy callback.
 *		      They are referenced, not copied, until
 *		      esdm_es_ext_server_free().
 * @param [in] socket_path Path of the socket file
 * @param [in] mode Access mode of the socket file, e.g. 0666
 * @param [out] server The server, to be released with
 *		       esdm_es_ext_server_free()
 *
 * @return 0 on success, -EPROTO for callbacks that do not fit this version of
 *	   the API, another negative errno otherwise - the one @init returned
 *	   included
 */
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server);

/**
 * @brief Serve only clients running as root and as @uid
 *
 * By default, any client that can connect to the socket is served. Once a user
 * is allowed, only clients running as root or as an allowed user are; any
 * other is disconnected right away, before it can take one of the few client
 * slots the server has - or drain the noise source. Allow the user the ESDM
 * runs as (user nobody by default): it connects as root at start up, but with
 * its privileges dropped once it reconnects. Up to 8 users can be allowed.
 *
 * @param [in] server The server, not running yet
 * @param [in] uid The user to allow
 *
 * @return 0 on success, -EINVAL for an invalid uid, -ENOSPC if 8 users are
 *	   allowed already
 */
int esdm_es_ext_server_allow_uid(struct esdm_es_ext_server *server, uid_t uid);

/**
 * @brief Offer DTLS to the clients, or not
 *
 * Not offered by default: the STARTDTLS request of a client is answered with
 * -EOPNOTSUPP and the client goes on unencrypted. Enabled in a library built
 * with DTLS support (meson option dtls), it is answered with a DTLS
 * handshake.
 *
 * @param [in] server The server, not running yet
 * @param [in] enable Whether DTLS is offered
 *
 * @return 0 on success, -EOPNOTSUPP to enable DTLS in a library built without
 *	   it, -ENOMEM if the DTLS context cannot be set up
 */
int esdm_es_ext_server_set_dtls(struct esdm_es_ext_server *server, int enable);

/**
 * @brief Answer INFO with another name than the one of the source
 *
 * The server declares the @name of its source as the name of the source by
 * default - see the INFO request above. A name set here is declared instead.
 *
 * @param [in] server The server, not running yet
 * @param [in] name 1 to ESDM_ES_EXT_NAME_MAX bytes of UTF-8 without control
 *		    characters, NUL-terminated; NULL to go back to the name of
 *		    the source
 *
 * @return 0 on success, -EINVAL for a name that is not valid
 */
int esdm_es_ext_server_set_name(struct esdm_es_ext_server *server,
				const char *name);

/**
 * @brief Answer INFO with another entropy rate than the one of the source
 *
 * The server declares the rate the @entropy_rate callback of its source
 * returns by default, none for a source without one - see the INFO request
 * above. A rate set here is declared instead.
 *
 * @param [in] server The server, not running yet
 * @param [in] rate Bits of entropy per 256 bits of data, 0 to
 *		    ESDM_ES_EXT_ENTROPY_RATE_MAX; ESDM_ES_EXT_PROTO_RATE_NONE to
 *		    go back to the rate of the source
 *
 * @return 0 on success, -EINVAL for a rate out of range
 */
int esdm_es_ext_server_set_entropy_rate(struct esdm_es_ext_server *server,
					uint32_t rate);

/**
 * @brief Serve requests until esdm_es_ext_server_stop() is called
 *
 * Serves the clients connected at a time one request after the other. A
 * client that breaks the protocol is disconnected. Up to 8 clients are served
 * at a time: when another one connects, the client that sent nothing for the
 * longest time is disconnected to make room for it - one running as root only
 * for another one running as root, as the ESDM connects as root at start up.
 * Clients holding their slots without using them so cannot lock the ESDM out,
 * which connects again at once when it finds its connection closed.
 *
 * @param [in] server The server
 *
 * @return 0 once stopped, a negative errno if serving failed
 */
int esdm_es_ext_server_run(struct esdm_es_ext_server *server);

/**
 * @brief Make esdm_es_ext_server_run() return
 *
 * May be called from another thread and from a signal handler.
 *
 * @param [in] server The server
 */
void esdm_es_ext_server_stop(struct esdm_es_ext_server *server);

/**
 * @brief Release the server
 *
 * Closes the connections, removes the socket file and calls the @fini callback
 * of the source. Must not be called while esdm_es_ext_server_run() runs.
 *
 * @param [in] server The server, may be NULL
 */
void esdm_es_ext_server_free(struct esdm_es_ext_server *server);

/******************************************************************************
 * Provider program - libesdm_es_ext
 ******************************************************************************/

/**
 * @brief Run a provider program serving an external entropy source
 *
 * The main() of a provider program: it takes the command line of @argc and
 * @argv, sets up the source - calls the @init callback of @plugin - and
 * serves it on a Unix domain socket until SIGTERM, SIGINT or SIGHUP - see
 * libesdm_es_ext(3) for the options:
 *
 *	-s, --socket PATH	the Unix domain socket to serve on
 *	-m, --mode MODE		its access mode, 0666 by default
 *	-u, --client_uid USER	the users served next to root, nobody by
 *				default - see esdm_es_ext_server_allow_uid()
 *	--no_dtls		no DTLS - see esdm_es_ext_server_set_dtls()
 *	--name NAME		the name declared in place of @name
 *	--entropy_rate BITS	the rate declared in place of @entropy_rate
 *	-v, -h, --version
 *
 * The signals are blocked in every thread from the start, so that a thread
 * the @init callback starts does not take them. Once it serves, it tells
 * systemd so where it runs as a service of Type=notify.

 *
 * The program is to call it once, from its main(), and return what it
 * returns: it parses the command line with getopt_long(3), and serves one
 * source per process. The library logs to stderr.
 *
 * @param [in] plugin The callbacks of the entropy source to serve, see
 *		      esdm_es_ext_server_alloc()
 * @param [in] argc The argument count of main()
 * @param [in] argv The arguments of main(); argv[0] names the program in its
 *		    usage
 *
 * @return the exit status of the program: 0 once a signal ended it, or for
 *	   --help and --version; 1 for a command line that is wrong, a source
 *	   that cannot be set up or served - told on stderr - or serving that
 *	   failed
 */
int esdm_es_ext_provider_main(const struct esdm_es_ext_plugin *plugin,
			      int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_ES_EXT_H */
