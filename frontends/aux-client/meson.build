# for i in $(ls *.c | sort); do echo "'$i',"; done
aux_client_src = files([
	'esdm_aux_need_entropy.c'
])

# Restrict the exports to the API - see version.lds, and esdm/meson.build on
# the probe.
esdm_aux_client_version_lds = meson.current_source_dir() / 'version.lds'
esdm_aux_client_link_args = [
	'-Wl,--version-script,' + esdm_aux_client_version_lds
]
if not cc.has_multi_link_arguments(esdm_aux_client_link_args)
	warning('Linker does not support version scripts - libesdm_aux_client.so exports every DSO_PUBLIC symbol')
	esdm_aux_client_link_args = []
endif

esdm_aux_client_lib = both_libraries('esdm_aux_client',
	[ aux_client_src ],
	include_directories: include_dirs_client,
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_aux_client_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_aux_client_lib)

include_user_files += files([
	'esdm_aux_client.h'
])
