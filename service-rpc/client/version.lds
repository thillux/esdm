/*
 * Linker version script for libesdm_rpc_client.
 *
 * The library links the static ESDM common library, whose DSO_PUBLIC symbols -
 * the logger and the thread pool - would otherwise leak out of
 * libesdm_rpc_client.so under their generic names, where any application
 * defining one of them would interpose it.
 *
 * LIBESDM_RPC_CLIENT_1.0 is the supported API as declared by the installed
 * header esdm_rpc_client.h, LIBESDM_RPC_CLIENT_PRIVATE_1.0 is what the in-tree
 * frontends additionally rely on, and everything else is hidden.
 *
 * Do not remove a symbol from LIBESDM_RPC_CLIENT_1.0 or rename the node
 * without bumping the library soversion. New API is added in a new node
 * (LIBESDM_RPC_CLIENT_1.1 { ... } LIBESDM_RPC_CLIENT_1.0;).
 */

LIBESDM_RPC_CLIENT_1.0 {
	global:
		/* General service handlers */
		esdm_rpcc_set_max_online_nodes;

		/* Unprivileged ESDM interface */
		esdm_rpcc_get_unpriv_service;
		esdm_rpcc_put_unpriv_service;
		esdm_rpcc_init_unpriv_service;
		esdm_rpcc_fini_unpriv_service;
		esdm_rpcc_force_fini_unpriv_service;

		/* Privileged ESDM interface */
		esdm_rpcc_get_priv_service;
		esdm_rpcc_put_priv_service;
		esdm_rpcc_init_priv_service;
		esdm_rpcc_fini_priv_service;
		esdm_rpcc_force_fini_priv_service;

		/* RPC service call APIs */
		esdm_rpcc_status;
		esdm_rpcc_status_int;
		esdm_rpcc_status_json;
		esdm_rpcc_status_json_int;
		esdm_rpcc_drng_status_json;
		esdm_rpcc_drng_status_json_int;
		esdm_rpcc_drng_status_pr_json;
		esdm_rpcc_drng_status_pr_json_int;
		esdm_rpcc_get_ent_lvl;
		esdm_rpcc_get_ent_lvl_int;
		esdm_rpcc_is_fully_seeded;
		esdm_rpcc_is_fully_seeded_int;
		esdm_rpcc_get_random_bytes_full;
		esdm_rpcc_get_random_bytes_full_int;
		esdm_rpcc_get_random_bytes_full_timeout;
		esdm_rpcc_get_random_bytes_full_timeout_int;
		esdm_rpcc_get_random_bytes_pr;
		esdm_rpcc_get_random_bytes_pr_int;
		esdm_rpcc_get_random_bytes_pr_nonblock;
		esdm_rpcc_get_random_bytes_pr_nonblock_int;
		esdm_rpcc_get_random_bytes;
		esdm_rpcc_get_random_bytes_int;
		esdm_rpcc_get_seed;
		esdm_rpcc_get_seed_int;
		esdm_rpcc_write_data;
		esdm_rpcc_write_data_int;
		esdm_rpcc_rnd_get_ent_cnt;
		esdm_rpcc_rnd_get_ent_cnt_int;
		esdm_rpcc_rnd_add_to_ent_cnt;
		esdm_rpcc_rnd_add_to_ent_cnt_int;
		esdm_rpcc_rnd_add_entropy;
		esdm_rpcc_rnd_add_entropy_int;
		esdm_rpcc_rnd_clear_pool;
		esdm_rpcc_rnd_clear_pool_int;
		esdm_rpcc_rnd_reseed_crng;
		esdm_rpcc_rnd_reseed_crng_int;
		esdm_rpcc_get_poolsize;
		esdm_rpcc_get_poolsize_int;
		esdm_rpcc_get_write_wakeup_thresh;
		esdm_rpcc_get_write_wakeup_thresh_int;
		esdm_rpcc_set_write_wakeup_thresh;
		esdm_rpcc_set_write_wakeup_thresh_int;
		esdm_rpcc_get_min_reseed_secs;
		esdm_rpcc_get_min_reseed_secs_int;
		esdm_rpcc_set_min_reseed_secs;
		esdm_rpcc_set_min_reseed_secs_int;
		esdm_rpcc_set_pkcs11_config;
		esdm_rpcc_set_pkcs11_config_int;
		esdm_rpcc_selftest;
		esdm_rpcc_selftest_int;
		esdm_rpcc_jent_status;
		esdm_rpcc_jent_status_int;

	local:
		*;
};

/*
 * Not API - see the LIBESDM_PRIVATE_1.0 node of libesdm, which exports the
 * logger for the same reason.
 *
 * The logger keeps its verbosity and its syslog switch in the static library,
 * so the library holds a copy of its own. The ESDM frontends link that static
 * library as well and configure their copy from the command line. With the
 * logger exported, the frontend's copy interposes the library's and the
 * messages of the RPC client obey -v and the syslog option like every other
 * message of the frontend. Hidden, the library would log into a copy nobody
 * configures, which drops even its error messages.
 *
 * The thread pool is not needed here: nothing in the client uses it, it is
 * only linked for the thread name in the log records.
 */
LIBESDM_RPC_CLIENT_PRIVATE_1.0 {
	global:
		/* esdm_logger.h */
		_esdm_logger;
		esdm_logger_enable_syslog;
		esdm_logger_set_verbosity;
} LIBESDM_RPC_CLIENT_1.0;
