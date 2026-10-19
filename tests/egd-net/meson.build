# Tests of the EGD protocol over the network: the TLS layer, the network modes
# of the client library, and the esdm-egd-net-server and -relay daemons.
#
# The test PKI they use is committed next to them - see pki/gen.sh.
egd_net_pki = meson.current_source_dir() / 'pki'

egd_net_test_args = [ '-DESDM_TEST_PKI="' + egd_net_pki + '"' ]

# The TLS layer for the TLS stack of the build, both ends in one process.
# Skips (77) in a build without egd-net-tls.
egd_net_tls_test = executable(
		'egd_net_tls_test',
		[ 'tls_test.c' ],
		c_args: egd_net_test_args,
		include_directories: include_dirs_server,
		dependencies: [ dependency('threads') ] + egd_net_tls_deps,
		link_with: esdm_common_static_lib
	)

test('EGD network TLS layer', egd_net_tls_test, timeout: 120,
	suite: 'egd-net')

# The addresses of the network, the allowlist and the keyed bounds of the
# daemons, compiled in.
egd_net_common_test = executable(
		'egd_net_common_test',
		[ 'common_test.c', egd_net_common_src ],
		include_directories: include_dirs_egd_net,
		dependencies: [ dependency('threads') ] + egd_net_tls_deps,
		link_with: esdm_common_static_lib
	)

test('EGD network addresses', egd_net_common_test, suite: 'egd-net')

# The esdm-egd-net-server, its bounds, its rotation and revocation, plain TCP
# and the allowlist. Needs no ESDM, and no privileges: the commands it speaks
# are answered by the daemon itself.
egd_net_server_test = executable(
		'egd_net_server_test',
		[ 'server_test.c' ],
		c_args: egd_net_test_args,
		include_directories: [ include_dirs_egd_net ],
		dependencies: [ dependency('threads') ] + egd_net_tls_deps,
		link_with: [ esdm_egd_client_linked_lib,
			     esdm_common_static_lib ]
	)

test('EGD network server', egd_net_server_test,
	env: [ 'ESDM_EGD_NET_SERVER=' + esdm_egd_net_server.full_path() ],
	depends: [ esdm_egd_net_server ],
	timeout: 300, suite: 'egd-net')

# The network modes of the client library against a server the test plays:
# a connection the server closed is replaced.
egd_net_client_test = executable(
		'egd_net_client_test',
		[ 'client_test.c' ],
		c_args: egd_net_test_args,
		include_directories: [ include_dirs_egd_net ],
		dependencies: [ dependency('threads') ] + egd_net_tls_deps,
		link_with: [ esdm_egd_client_linked_lib,
			     esdm_common_static_lib ]
	)

test('EGD network client', egd_net_client_test, timeout: 120,
	suite: 'egd-net')

if get_option('esdm-server').enabled()
	# Every command through the network server and the relay, in TLS and
	# plain TCP, against an esdm-server - which takes root: skips (77)
	# otherwise. Isolated in namespaces of its own, like the EGD server
	# test.
	egd_net_relay_test = executable(
			'egd_net_relay_test',
			[ 'relay_test.c' ],
			c_args: egd_net_test_args,
			include_directories: [ include_dirs_egd_net ],
			dependencies: [ dependency('threads') ] + egd_net_tls_deps,
			link_with: [ esdm_egd_client_linked_lib,
				     esdm_common_static_lib ]
		)

	test('EGD network end to end', egd_net_relay_test,
		env: [ 'ESDM_SERVER=' + esdm_server.full_path(),
		       'ESDM_EGD_NET_SERVER=' + esdm_egd_net_server.full_path(),
		       'ESDM_EGD_NET_RELAY=' + esdm_egd_net_relay.full_path() ],
		depends: [ esdm_server, esdm_egd_net_server, esdm_egd_net_relay ],
		timeout: 600, suite: 'egd-net')
endif

# The shared library loads no TLS stack until a client in TLS mode is
# allocated, which loads its TLS module - the one of the build tree here.
if egd_net_tls
	egd_net_module_test = executable(
			'egd_net_module_test',
			[ 'module_test.c' ],
			c_args: egd_net_test_args,
			include_directories: [ include_dirs_egd_net ],
			dependencies: [ dependency('threads') ],
			link_with: [ esdm_egd_client_lib.get_shared_lib() ]
		)

	test('EGD client TLS module', egd_net_module_test,
		env: [ 'ESDM_EGD_NET_SERVER=' + esdm_egd_net_server.full_path(),
		       'ESDM_EGD_TLS_MODULE=' + esdm_egd_tls_module.full_path() ],
		depends: [ esdm_egd_net_server, esdm_egd_tls_module ],
		timeout: 120, suite: 'egd-net')
endif
