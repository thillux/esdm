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

test('External ES provider on the network', es_ext_net_server_test,
	args: [ esdm_es_ext_serve.full_path(),
		es_ext_test_plugin.full_path() ],
	depends: [ esdm_es_ext_serve, es_ext_test_plugin ],
	timeout: 300, suite: 'es-ext-net')
