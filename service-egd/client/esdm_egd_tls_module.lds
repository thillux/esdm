/*
 * Linker version script for the TLS module of libesdm_egd_client,
 * esdm-egd-tls.so - see esdm_egd_client_tls.h. The library looks up its
 * entry point and nothing else; the common code the module links, the logger
 * among it, stays hidden.
 */

{
	global:
		esdm_egd_tls_module;

	local:
		*;
};
