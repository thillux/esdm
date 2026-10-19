# libesdm_es_ext: what an external entropy source is developed against - the
# plugin API of esdm_es_ext.h, the provider server serving a plugin on a Unix
# domain socket, and the loader for plugin libraries. Its only dependencies
# beyond libc are the ESDM logger, the socket creation of the server, and
# json-c for the status the server answers with.
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
	dependencies: [ dependency('threads'), dl_dep, json_c_dep ] + dtls_deps,
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
	dependencies: [ dependency('threads'), dl_dep, json_c_dep ] + dtls_deps,
	install: true
	)

# The PKCS#11 entropy source: a provider of its own, serving the random number
# generator of a PKCS#11 token with the provider server above - see
# esdm-es-pkcs11(8). It is the only part of the ESDM that needs libp11.
if get_option('es_pkcs11').enabled()
	esdm_es_pkcs11 = executable('esdm-es-pkcs11',
		[ 'pkcs11/esdm_es_pkcs11.c', 'pkcs11/esdm_es_pkcs11_main.c' ],
		c_args: [ '-DESDM_ES_PKCS11_VERSION="' + meson.project_version() + '"' ],
		include_directories: include_dirs_es_ext,
		link_with: [ esdm_es_ext_lib.get_static_lib(), esdm_common_static_lib ],
		dependencies: [ dependency('threads'), dl_dep, json_c_dep,
				dependency('libp11', required: true) ] + dtls_deps,
		install: true
		)

	# Its systemd unit, and the system user it runs as - see the unit
	es_pkcs11_conf_data = configuration_data()
	es_pkcs11_conf_data.set('PATH',
		get_option('prefix') + '/' + get_option('bindir'))
	# Ready once it serves, which it tells systemd where it can
	es_pkcs11_conf_data.set('SERVICE_TYPE',
		get_option('systemd').enabled() ? 'Type=notify' : 'Type=exec')
	esdm_es_pkcs11_service = configure_file(
		input: 'pkcs11/esdm-es-pkcs11.service.in',
		output: 'esdm-es-pkcs11.service',
		configuration: es_pkcs11_conf_data)
	install_data(esdm_es_pkcs11_service,
		install_dir: get_option('prefix') / 'lib/systemd/system')
	install_data('pkcs11/esdm-es-pkcs11.sysusers',
		rename: 'esdm-es-pkcs11.conf',
		install_dir: get_option('prefix') / 'lib/sysusers.d')
endif
