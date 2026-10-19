# for i in $(ls *.c | sort); do echo "'$i',"; done
client_rpc_src = files([
	'esdm_rpc_client.c',
	'esdm_rpc_get_ent_lvl_c.c',
	'esdm_rpc_get_min_reseed_secs_c.c',
	'esdm_rpc_get_poolsize_c.c',
	'esdm_rpc_get_random_bytes_c.c',
	'esdm_rpc_get_random_bytes_full_c.c',
	'esdm_rpc_get_random_bytes_full_timeout_c.c',
	'esdm_rpc_get_random_bytes_pr_c.c',
	'esdm_rpc_get_seed_c.c',
	'esdm_rpc_get_write_wakeup_thresh_c.c',
	'esdm_rpc_is_fully_seeded_c.c',
	'esdm_rpc_jent_status_c.c',
	'esdm_rpc_rnd_add_entropy_c.c',
	'esdm_rpc_rnd_add_to_ent_cnt_c.c',
	'esdm_rpc_rnd_clear_pool_c.c',
	'esdm_rpc_rnd_get_ent_cnt_c.c',
	'esdm_rpc_rnd_reseed_crng_c.c',
	'esdm_rpc_selftest_c.c',
	'esdm_rpc_set_min_reseed_secs_c.c',
	'esdm_rpc_set_write_wakeup_thresh_c.c',
	'esdm_rpc_status_c.c',
	'esdm_rpc_drng_status_json_c.c',
	'esdm_rpc_status_json_c.c',
	'esdm_rpc_write_data_c.c'
])

# Restrict the exports to the API - see version.lds, and esdm/meson.build on
# the probe.
esdm_rpc_client_version_lds = meson.current_source_dir() / 'version.lds'
esdm_rpc_client_link_args = [
	'-Wl,--version-script,' + esdm_rpc_client_version_lds
]
if not cc.has_multi_link_arguments(esdm_rpc_client_link_args)
	warning('Linker does not support version scripts - libesdm_rpc_client.so exports every DSO_PUBLIC symbol')
	esdm_rpc_client_link_args = []
endif

esdm_rpc_client_lib = both_libraries('esdm_rpc_client',
	[ service_rpc_src, client_rpc_src ],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client ],
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_rpc_client_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_rpc_client_lib)

include_user_files += files([
	'esdm_rpc_client.h'
])
