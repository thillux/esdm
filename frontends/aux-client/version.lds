/*
 * Linker version script for libesdm_aux_client.
 *
 * The library links the static ESDM common library, whose DSO_PUBLIC symbols -
 * the logger and the thread pool - would otherwise leak out of
 * libesdm_aux_client.so under their generic names, where any application
 * defining one of them would interpose it.
 *
 * LIBESDM_AUX_CLIENT_1.0 is the supported API as declared by the installed
 * header esdm_aux_client.h, LIBESDM_AUX_CLIENT_PRIVATE_1.0 is what esdm-tool
 * additionally relies on, and everything else is hidden.
 *
 * Do not remove a symbol from LIBESDM_AUX_CLIENT_1.0 or rename the node
 * without bumping the library soversion. New API is added in a new node
 * (LIBESDM_AUX_CLIENT_1.1 { ... } LIBESDM_AUX_CLIENT_1.0;).
 */

LIBESDM_AUX_CLIENT_1.0 {
	global:
		esdm_aux_init_wait_for_need_entropy;
		esdm_aux_fini_wait_for_need_entropy;
		esdm_aux_timedwait_for_need_entropy;

	local:
		*;
};

/*
 * Not API - see LIBESDM_RPC_CLIENT_PRIVATE_1.0 of libesdm_rpc_client: exported
 * so that the logger of esdm-tool, which links this library, interposes the
 * library's own copy and the error messages of the library obey the logging
 * options of the tool instead of being dropped.
 */
LIBESDM_AUX_CLIENT_PRIVATE_1.0 {
	global:
		/* esdm_logger.h */
		_esdm_logger;
		esdm_logger_enable_syslog;
		esdm_logger_set_verbosity;
} LIBESDM_AUX_CLIENT_1.0;
