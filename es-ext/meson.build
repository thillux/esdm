# libesdm_es_ext: what an external entropy source is developed against - the
# callbacks of a source of esdm_es_ext.h, the provider server serving them on
# a Unix domain socket, and the provider program around it, with its command
# line. Its only dependencies beyond libc are the ESDM logger, the socket
# creation of the server, and json-c for the status the server answers with -
# and with es-ext-net, the TLS stack of the crypto backend for the network
# mode of the server, and the drop of the privileges of the program on the
# network - see net/esdm_es_ext_net_cli.h.
es_ext_lib_src = files([
	'esdm_es_ext_provider.c',
	'esdm_es_ext_server.c',
	'net/esdm_es_ext_net_cli.c',
	'../service-egd/server/esdm_server_socket.c',
])
if es_ext_net
	es_ext_lib_src += files([ '../service-rpc/server/privileges.c' ])
endif
include_dirs_es_ext_lib = [ include_dirs_es_ext,
			    include_directories('net',
						'../service-rpc/server') ]

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
	include_directories: include_dirs_es_ext_lib,
	dependencies: [ dependency('threads'), json_c_dep ] + dtls_deps +
		      es_ext_net_deps,
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

# The relay of a provider on another host: a local provider socket for the
# ESDM, forwarded to a provider served on the network - see
# esdm-es-ext-relay(8). The provider protocol, the DTLS of both sides and the
# creation of the local socket; nothing of the provider server.
if es_ext_net
	esdm_es_ext_relay = executable('esdm-es-ext-relay',
		[ 'relay/esdm_es_ext_relay.c',
		  '../service-rpc/server/privileges.c',
		  '../service-egd/server/esdm_server_socket.c' ],
		c_args: [ '-DESDM_ES_EXT_RELAY_VERSION="' + meson.project_version() + '"' ],
		include_directories: include_dirs_es_ext_lib,
		link_with: [ esdm_common_static_lib ],
		dependencies: [ dependency('threads') ] + dtls_deps +
			      es_ext_net_deps,
		install: true
		)

	# The unit of the relay, and the system user it runs as - see the unit.
	# A provider on the network is a program of its own making, served by a
	# unit of its own - see NETWORK in libesdm_es_ext(3).
	es_ext_net_conf_data = configuration_data()
	es_ext_net_conf_data.set('PATH',
		get_option('prefix') / get_option('bindir'))
	es_ext_net_conf_data.set('PORT', get_option('es-ext-net-port'))
	# Ready once it serves, which it tells systemd where it can
	es_ext_net_conf_data.set('SERVICE_TYPE',
		get_option('systemd').enabled() ? 'Type=notify' : 'Type=exec')
	install_data(configure_file(
			input: 'relay/esdm-es-ext-relay.service.in',
			output: 'esdm-es-ext-relay.service',
			configuration: es_ext_net_conf_data),
		     install_dir: get_option('prefix') / 'lib/systemd/system')
	install_data('relay/esdm-es-ext-relay.sysusers',
		rename: 'esdm-es-ext-relay.conf',
		install_dir: get_option('prefix') / 'lib/sysusers.d')
endif

# The PKCS#11 entropy source: a provider of its own, serving the random number
# generator of a PKCS#11 token with the provider program above, its command
# line taking the options of the token - see esdm-es-pkcs11(8) and
# esdm_es_ext_provider.h, which it reaches in the static library. It is the
# only part of the ESDM that needs libp11.
if get_option('es_pkcs11').enabled()
	esdm_es_pkcs11 = executable('esdm-es-pkcs11',
		[ 'pkcs11/esdm_es_pkcs11.c', 'pkcs11/esdm_es_pkcs11_main.c' ],
		c_args: [ '-DESDM_ES_PKCS11_VERSION="' + meson.project_version() + '"' ],
		include_directories: include_dirs_es_ext_lib,
		link_with: [ esdm_es_ext_lib.get_static_lib(), esdm_common_static_lib ],
		# libcrypto for the error queue of OpenSSL, on which libp11
		# reports why a login failed - see esdm_es_pkcs11_login()
		dependencies: [ dependency('threads'), json_c_dep,
				dependency('libp11', required: true),
				dependency('libcrypto', required: true) ] +
			      dtls_deps + es_ext_net_deps,
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
