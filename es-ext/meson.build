# libesdm_es_ext: what an external entropy source is developed against - the
# plugin API of esdm_es_ext.h, the provider server serving a plugin on a Unix
# domain socket, and the loader for plugin libraries. Its only dependencies
# beyond libc are the ESDM logger and the socket creation of the server.
es_ext_lib_src = files([
	'esdm_es_ext_plugin.c',
	'esdm_es_ext_server.c',
	'../service-egd/server/esdm_server_socket.c',
])

# Restrict the exports to the API - see version.lds, and esdm/meson.build on
# the probe.
esdm_es_ext_version_lds = meson.current_source_dir() / 'version.lds'
esdm_es_ext_link_args = [
	'-Wl,--version-script,' + esdm_es_ext_version_lds
]
if not cc.has_multi_link_arguments(esdm_es_ext_link_args)
	warning('Linker does not support version scripts - libesdm_es_ext.so exports every DSO_PUBLIC symbol')
	esdm_es_ext_link_args = []
endif

esdm_es_ext_lib = both_libraries('esdm_es_ext',
	[ es_ext_lib_src ],
	include_directories: include_dirs_es_ext,
	dependencies: [ dependency('threads'), dl_dep ] + dtls_deps,
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_es_ext_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_es_ext_lib,
	description: 'Library to develop external entropy sources for the ESDM against')

include_user_files += files([
	'esdm_es_ext.h'
])

# A provider for any plugin library: what esdm-server --es_ext_lib loads into
# the daemon, served in a process of its own - see esdm-es-ext-serve(8).
esdm_es_ext_serve = executable('esdm-es-ext-serve',
	[ 'serve/esdm_es_ext_serve.c' ],
	c_args: [ '-DESDM_ES_EXT_SERVE_VERSION="' + meson.project_version() + '"' ],
	include_directories: include_dirs_es_ext,
	link_with: [ esdm_es_ext_lib.get_static_lib(), esdm_common_static_lib ],
	dependencies: [ dependency('threads'), dl_dep ] + dtls_deps,
	install: true
	)
