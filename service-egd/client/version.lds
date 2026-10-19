/*
 * Linker version script for libesdm_egd_client.
 *
 * The library links the static ESDM common library, whose DSO_PUBLIC symbols -
 * the logger and the thread pool - would otherwise leak out of
 * libesdm_egd_client.so under their generic names, where any application
 * defining one of them would interpose it.
 *
 * LIBESDM_EGD_CLIENT_1.0 is the supported API as declared by the installed
 * header esdm_egd_client.h, everything else is hidden. Unlike the RPC client,
 * no ESDM frontend links this library as a shared object, so there is no
 * logger of a frontend to share and the logger stays hidden as well.
 *
 * Do not remove a symbol from LIBESDM_EGD_CLIENT_1.0 or rename the node
 * without bumping the library soversion. New API is added in a new node
 * (LIBESDM_EGD_CLIENT_1.1 { ... } LIBESDM_EGD_CLIENT_1.0;).
 *
 * LIBESDM_EGD_CLIENT_1.1 adds the network modes and the ESDM commands beyond
 * the reads. esdm_egd_client_alloc_net() exists in every build - it reports
 * -EOPNOTSUPP in one without the network modes.
 */

LIBESDM_EGD_CLIENT_1.0 {
	global:
		esdm_egd_client_alloc;
		esdm_egd_client_free;
		esdm_egd_client_socket_path;
		esdm_egd_client_get_random;
		esdm_egd_client_get_random_nonblock;
		esdm_egd_client_get_random_pr;
		esdm_egd_client_get_random_pr_nonblock;

		esdm_egd_client_entropy_count;
		esdm_egd_client_write_entropy;
		esdm_egd_client_get_pid;

	local:
		*;
};

LIBESDM_EGD_CLIENT_1.1 {
	global:
		esdm_egd_client_alloc_net;
		esdm_egd_client_get_random_unseeded;
		esdm_egd_client_get_state;
		esdm_egd_client_status;
		esdm_egd_client_status_json;
} LIBESDM_EGD_CLIENT_1.0;
