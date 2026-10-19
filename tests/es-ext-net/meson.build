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
