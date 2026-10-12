# Client for the EGD interface of the ESDM. Deliberately dependency free
# beyond the ESDM logger: everything it needs is one Unix domain stream
# socket, which is what makes it usable where the RPC client is not.
egd_client_src = files([
	'esdm_egd_client.c'
])

# Restrict the exports to the API - see version.lds, and esdm/meson.build on
# the probe.
esdm_egd_client_version_lds = meson.current_source_dir() / 'version.lds'
esdm_egd_client_link_args = [
	'-Wl,--version-script,' + esdm_egd_client_version_lds
]
if not cc.has_multi_link_arguments(esdm_egd_client_link_args)
	warning('Linker does not support version scripts - libesdm_egd_client.so exports every DSO_PUBLIC symbol')
	esdm_egd_client_link_args = []
endif

esdm_egd_client_lib = both_libraries('esdm_egd_client',
	[ egd_client_src ],
	include_directories: include_dirs_egd_client,
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_egd_client_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_egd_client_lib)

include_user_files += files([
	'esdm_egd_client.h'
])
