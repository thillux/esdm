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
 * ESDM. It is written once against struct esdm_es_ext_plugin below and handed
 * to the ESDM in one of two ways:
 *
 * - As a plugin: a shared library exporting the struct under the name
 *   ESDM_ES_EXT_PLUGIN_SYMBOL. The ESDM loads it into its own process
 *   (esdm-server --es_ext_lib PATH, meson option es_ext_lib_path) and calls it
 *   directly. Nothing but this header is needed to build such a plugin.
 *
 * - As a provider: a process of its own that serves the plugin over a Unix
 *   domain socket with esdm_es_ext_server_*() of libesdm_es_ext. The ESDM
 *   connects to it (esdm-server --es_ext_socket PATH, meson option
 *   es_ext_socket_path). esdm-es-ext-serve(8) does so for a plugin library, so
 *   the same plugin can run either way. The protocol is documented below for
 *   providers written without the library.
 *
 * Either way, the ESDM credits a block with the entropy the source claims for
 * it, but at most with what its configured entropy rate allows, and with
 * nothing for a block whose claim exceeds its size.
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
 * Plugin API
 ******************************************************************************/

/* Version of struct esdm_es_ext_plugin a plugin is written against */
#define ESDM_ES_EXT_PLUGIN_VERSION 1

/* The name a plugin library exports its struct esdm_es_ext_plugin under */
#define ESDM_ES_EXT_PLUGIN_SYMBOL "esdm_es_ext_plugin"

/* Makes the struct visible in a library built with -fvisibility=hidden */
#define ESDM_ES_EXT_PLUGIN_EXPORT __attribute__((visibility("default")))

/**
 * struct esdm_es_ext_plugin - an external entropy source
 *
 * A plugin library defines exactly one of these, e.g.
 *
 *	ESDM_ES_EXT_PLUGIN_EXPORT
 *	const struct esdm_es_ext_plugin esdm_es_ext_plugin = {
 *		.version = ESDM_ES_EXT_PLUGIN_VERSION,
 *		.name = "my-noise-source",
 *		.get_entropy = my_get_entropy,
 *	};
 *
 * The callbacks are never called concurrently: the ESDM, and the provider
 * server of libesdm_es_ext, serialize them.
 *
 * The ESDM loads a plugin and calls @init while it still has its privileges -
 * a device the plugin needs is to be opened there. Afterwards the ESDM drops
 * its privileges and isolates itself in namespaces of its own; @get_entropy
 * runs in that environment.
 *
 * @version: ESDM_ES_EXT_PLUGIN_VERSION
 * @name: Name of the source, shown in the ESDM status. May be NULL.
 * @init: Set the source up and return its context in *ctx, which is handed to
 *	  the other callbacks. Returns 0 or a negative errno, in which case the
 *	  source is not used. May be NULL.
 * @fini: Tear the source down. May be NULL.
 * @get_entropy: Fill all @buflen bytes of @buf with data of the noise source
 *		 and set *@entropy_bits to the entropy they hold, at most
 *		 @buflen * 8. Returns 0, or a negative errno if the source could
 *		 not deliver - the data is discarded then. Must not block for
 *		 long: it runs while a DRNG waits for its seed.
 * @selftest: Check that the source still works, without consuming the data
 *	      the ESDM is handed. Returns 0 or a negative errno. Run at start up
 *	      and on the interval of the ESDM self tests. May be NULL.
 */
struct esdm_es_ext_plugin {
	uint32_t version;
	const char *name;
	int (*init)(void **ctx);
	void (*fini)(void *ctx);
	int (*get_entropy)(void *ctx, uint8_t *buf, size_t buflen,
			   uint32_t *entropy_bits);
	int (*selftest)(void *ctx);
};

/******************************************************************************
 * Socket protocol
 *
 * The ESDM connects to the provider's SOCK_SEQPACKET Unix domain socket and
 * sends requests on the connection, one at a time; the provider answers each
 * with exactly one response. Requests and responses are one message each. All
 * integers are little endian.
 *
 * Request, ESDM_ES_EXT_PROTO_REQ_LEN bytes:
 *	u32 magic		ESDM_ES_EXT_PROTO_MAGIC
 *	u16 version		ESDM_ES_EXT_PROTO_VERSION
 *	u16 type		ESDM_ES_EXT_PROTO_GET_ENTROPY or
 *				ESDM_ES_EXT_PROTO_SELFTEST
 *	u32 length		bytes asked for, 1 to ESDM_ES_EXT_PROTO_MAX_DATA
 *				for GET_ENTROPY, 0 for SELFTEST
 *
 * Response, ESDM_ES_EXT_PROTO_RSP_LEN bytes followed by the data:
 *	u32 magic		ESDM_ES_EXT_PROTO_MAGIC
 *	u16 version		ESDM_ES_EXT_PROTO_VERSION
 *	u16 type		type of the request answered
 *	s32 status		0, or a negative errno
 *	u32 entropy_bits	entropy of the data, at most 8 * length
 *	u8  data[]		exactly length bytes for a GET_ENTROPY answered
 *				with status 0, nothing otherwise
 *
 * A response that breaks any of this is discarded and the connection closed.
 * A provider closes a connection on a request that breaks it.
 ******************************************************************************/

#define ESDM_ES_EXT_PROTO_MAGIC 0x58455345 /* "ESEX" in memory */
#define ESDM_ES_EXT_PROTO_VERSION 1
#define ESDM_ES_EXT_PROTO_GET_ENTROPY 1
#define ESDM_ES_EXT_PROTO_SELFTEST 2
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
 * @init callback of @plugin. An existing socket file at @socket_path is
 * replaced, any other file is not. The ESDM connects with its privileges
 * dropped (user nobody by default), so the socket has to be connectable for
 * that user - see esdm-server(8) on how the ESDM checks the provider in turn.
 *
 * @param [in] plugin The entropy source to serve. It is referenced, not copied,
 *		      until esdm_es_ext_server_free().
 * @param [in] socket_path Path of the socket file
 * @param [in] mode Access mode of the socket file, e.g. 0666
 * @param [out] server The server, to be released with
 *		       esdm_es_ext_server_free()
 *
 * @return 0 on success, a negative errno otherwise
 */
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server);

/**
 * @brief Serve requests until esdm_es_ext_server_stop() is called
 *
 * Serves the clients connected at a time one request after the other. A
 * client that breaks the protocol is disconnected.
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
 * of the plugin. Must not be called while esdm_es_ext_server_run() runs.
 *
 * @param [in] server The server, may be NULL
 */
void esdm_es_ext_server_free(struct esdm_es_ext_server *server);

/******************************************************************************
 * Plugin loader - libesdm_es_ext
 ******************************************************************************/

struct esdm_es_ext_plugin_handle;

/**
 * @brief Load a plugin library
 *
 * Loads the shared library @path and checks the struct esdm_es_ext_plugin it
 * exports: its version has to be ESDM_ES_EXT_PLUGIN_VERSION and it has to have
 * a @get_entropy callback. The @init callback is not called - the plugin is
 * meant to be handed to esdm_es_ext_server_alloc(), which does.
 *
 * @param [in] path Path of the plugin library
 * @param [out] handle Handle of the loaded library, to be released with
 *		       esdm_es_ext_plugin_unload()
 * @param [out] plugin The plugin, valid until the handle is released
 *
 * @return 0 on success, -ENOENT if the library cannot be loaded, -ENOEXEC if it
 *	   does not export a plugin, -EPROTO if the plugin does not fit this
 *	   version of the API
 */
int esdm_es_ext_plugin_load(const char *path,
			    struct esdm_es_ext_plugin_handle **handle,
			    const struct esdm_es_ext_plugin **plugin);

/**
 * @brief Unload a plugin library
 *
 * @param [in] handle Handle of the library, may be NULL
 */
void esdm_es_ext_plugin_unload(struct esdm_es_ext_plugin_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_ES_EXT_H */
