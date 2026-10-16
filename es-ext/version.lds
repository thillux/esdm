/*
 * Linker version script for libesdm_es_ext - the API of esdm_es_ext.h. The
 * protocol and plugin helpers of esdm_es_ext_proto.h are static inline and
 * the common code the library is linked with is not exported.
 */

LIBESDM_ES_EXT_1.0 {
	global:
		esdm_es_ext_plugin_load;
		esdm_es_ext_plugin_unload;
		esdm_es_ext_server_alloc;
		esdm_es_ext_server_allow_uid;
		esdm_es_ext_server_free;
		esdm_es_ext_server_run;
		esdm_es_ext_server_set_dtls;
		esdm_es_ext_server_stop;

	local:
		*;
};
