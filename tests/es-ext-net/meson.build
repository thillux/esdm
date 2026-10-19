# Tests of the external entropy sources on the network: DTLS over SCTP of the
# TLS layer, the network mode of the provider server, and the
# esdm-es-ext-relay - see the file headers. Each skips (77) on a kernel
# without SCTP.
#
# The test PKI is the one of the EGD network tests.
es_ext_net_pki = meson.project_source_root() / 'tests' / 'egd-net' / 'pki'

es_ext_net_test_args = [ '-DESDM_TEST_PKI="' + es_ext_net_pki + '"' ]

# DTLS over SCTP for the TLS stack of the build, both ends in one process
es_ext_net_dtls_test = executable(
		'es_ext_net_dtls_test',
		[ 'dtls_test.c' ],
		c_args: es_ext_net_test_args,
		include_directories: include_dirs_server,
		dependencies: [ dependency('threads') ] + es_ext_net_deps,
		link_with: esdm_common_static_lib
	)

test('DTLS over SCTP', es_ext_net_dtls_test, timeout: 120,
	suite: 'es-ext-net')

include_dirs_es_ext_net_test = [ include_dirs_server, include_dirs_es_ext ]

# The network mode of the provider server, as esdm-es-ext-serve has it,
# serving the test plugin: its bounds, allowlist, timeouts and rotation. Needs
# no privileges.
es_ext_net_server_test = executable(
		'es_ext_net_server_test',
		[ 'server_test.c' ],
		c_args: es_ext_net_test_args,
		include_directories: include_dirs_es_ext_net_test,
		dependencies: [ dependency('threads'), json_c_dep ] +
			      es_ext_net_deps,
		link_with: esdm_common_static_lib
	)

# The esdm-es-ext-relay between a client speaking the protocol as the ESDM
# does and esdm-es-ext-serve on the network. Needs no privileges.
es_ext_net_relay_test = executable(
		'es_ext_net_relay_test',
		[ 'relay_test.c' ],
		c_args: es_ext_net_test_args,
		include_directories: include_dirs_es_ext_net_test,
		dependencies: [ dependency('threads'), json_c_dep ] +
			      dtls_deps + es_ext_net_deps,
		link_with: esdm_common_static_lib
	)

test('External ES relay', es_ext_net_relay_test,
	args: [ esdm_es_ext_relay.full_path(), esdm_es_ext_serve.full_path(),
		es_ext_test_plugin_rated.full_path() ],
	depends: [ esdm_es_ext_relay, esdm_es_ext_serve,
		   es_ext_test_plugin_rated ],
	timeout: 300, suite: 'es-ext-net')

if get_option('es_ext').enabled() and get_option('esdm-server').enabled()
	# The esdm-server reading a provider on the network through the
	# relay - which takes root: skips (77) otherwise. Isolated in
	# namespaces of its own, like the other tests of the server.
	es_ext_net_esdm_test = executable(
			'es_ext_net_esdm_test',
			[ 'esdm_test.c' ],
			c_args: es_ext_net_test_args,
			include_directories: [ include_dirs_es_ext_net_test,
					       include_dirs_client ],
			dependencies: [ dependency('threads'), json_c_dep ] +
				      dependencies_client,
			link_with: [ esdm_common_static_lib,
				     esdm_rpc_client_lib ]
		)

	test('External ES on the network read by the ESDM',
		es_ext_net_esdm_test,
		args: [ esdm_server.full_path(), esdm_es_ext_relay.full_path(),
			esdm_es_ext_serve.full_path(),
			es_ext_test_plugin_rated.full_path() ],
		env: [ 'ESDM_SERVER=' + esdm_server.full_path() ],
		depends: [ esdm_server, esdm_es_ext_relay, esdm_es_ext_serve,
			   es_ext_test_plugin_rated ],
		timeout: 300, suite: 'es-ext-net')
endif

test('External ES provider on the network', es_ext_net_server_test,
	args: [ esdm_es_ext_serve.full_path(),
		es_ext_test_plugin.full_path() ],
	depends: [ esdm_es_ext_serve, es_ext_test_plugin ],
	timeout: 300, suite: 'es-ext-net')
