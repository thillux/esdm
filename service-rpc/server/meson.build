# The engine of the esdm-server: its start, the privilege drop, its interfaces
# and its end. Part of every server, also of one without the RPC interface.
server_rpc_src = files([
	'esdm_rpc_server.c',
	'privileges.c'
])

# The handlers of the RPC calls and the two services they make up, left out of
# the build with esdm-server-rpc disabled - as is the RPC transport within
# esdm_rpc_server.c.
#
# for i in $(ls *_s.c esdm_rpc_service.c | sort); do echo "'$i',"; done
if get_option('esdm-server-rpc').enabled()
	server_rpc_src += files([
		'esdm_rpc_get_ent_lvl_s.c',
		'esdm_rpc_get_min_reseed_secs_s.c',
		'esdm_rpc_get_poolsize_s.c',
		'esdm_rpc_get_random_bytes_full_s.c',
		'esdm_rpc_get_random_bytes_pr_s.c',
		'esdm_rpc_get_random_bytes_s.c',
		'esdm_rpc_get_seed_s.c',
		'esdm_rpc_get_write_wakeup_thresh_s.c',
		'esdm_rpc_is_fully_seeded_s.c',
		'esdm_rpc_jent_status_s.c',
		'esdm_rpc_rnd_add_entropy_s.c',
		'esdm_rpc_rnd_add_to_ent_cnt_s.c',
		'esdm_rpc_rnd_clear_pool_s.c',
		'esdm_rpc_rnd_get_ent_cnt_s.c',
		'esdm_rpc_rnd_reseed_crng_s.c',
		'esdm_rpc_selftest_s.c',
		'esdm_rpc_set_es_rate_s.c',
		'esdm_rpc_service.c',
		'esdm_rpc_set_min_reseed_secs_s.c',
		'esdm_rpc_set_write_wakeup_thresh_s.c',
		'esdm_rpc_drng_status_json_s.c',
		'esdm_rpc_status_json_s.c',
		'esdm_rpc_status_s.c',
		'esdm_rpc_write_data_s.c',
	])
endif
