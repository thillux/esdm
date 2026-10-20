# The external entropy sources: the library they are developed against, the
# source of the ESDM reading them, and the providers the tests start - see the
# file headers.
if get_option('esdm-es-ext').enabled() or get_option('es_ext').enabled()
	include_dirs_es_ext_test = [ include_dirs_es_ext,
				     include_directories('../common') ]

	es_ext_proto_test = executable('es_ext_proto_test',
		'es_ext_proto_test.c',
		include_directories: include_dirs_es_ext_test,
	)
	test('External ES protocol', es_ext_proto_test, suite: 'es_ext')

	# The status of a provider, as the ESDM takes it
	if get_option('es_ext').enabled()
		es_ext_status_test = executable('es_ext_status_test',
			[ '../../esdm/es/esdm_es_ext_status.c',
			  'es_ext_status_test.c' ],
			include_directories: [ include_dirs_server,
					       include_dirs_es_ext_test ],
			dependencies: [ json_c_dep ],
			link_with: esdm_common_static_lib,
		)
		test('External ES status', es_ext_status_test, suite: 'es_ext')
	endif
endif

if get_option('esdm-es-ext').enabled()
	# Provider programs of the test source, steered through the
	# environment - see es_ext_test_plugin.c: one with all callbacks, one
	# without the callbacks a source may leave out - no status, no entropy
	# rate - and one declaring its name and its rate
	es_ext_test_providers = {}
	foreach kind, args : { '': [],
			       '_bare': [ '-DES_EXT_TEST_PLUGIN_BARE' ],
			       '_rated': [ '-DES_EXT_TEST_PLUGIN_RATED' ] }
		es_ext_test_providers += { kind: executable(
			'es_ext_test_provider' + kind,
			'es_ext_test_plugin.c',
			c_args: [ '-DES_EXT_TEST_PROVIDER' ] + args,
			include_directories: include_dirs_es_ext_test,
			link_with: [ esdm_es_ext_lib.get_static_lib(),
				     esdm_common_static_lib ],
			dependencies: [ dependency('threads'), json_c_dep ] +
				      dtls_deps + es_ext_net_deps,
		) }
	endforeach
	es_ext_test_provider = es_ext_test_providers['']
	es_ext_test_provider_rated = es_ext_test_providers['_rated']

	# The example of es-ext/example, reading a device every test system
	# has, so that it is built and run rather than only shipped: as a
	# provider of its own making is built, against the header as installed
	# - see include/esdm - and the shared library.
	subdir('include/esdm')
	es_ext_example = executable('es_ext_example',
		'../../es-ext/example/esdm_es_ext_example.c',
		c_args: [ '-DESDM_ES_EXT_EXAMPLE_DEVICE="/dev/urandom"' ],
		include_directories: include_directories('include'),
		implicit_include_directories: false,
		link_with: esdm_es_ext_lib.get_shared_lib(),
	)
	# The example once more, reading a FIFO the test creates and leaves
	# empty: a device that stalls
	es_ext_example_fifo = meson.current_build_dir() / 'es_ext_example.fifo'
	es_ext_example_fifo_provider = executable('es_ext_example_fifo',
		'../../es-ext/example/esdm_es_ext_example.c',
		c_args: [ '-DESDM_ES_EXT_EXAMPLE_DEVICE="' +
			  es_ext_example_fifo + '"' ],
		include_directories: include_directories('include'),
		implicit_include_directories: false,
		link_with: esdm_es_ext_lib.get_shared_lib(),
	)

	# The provider server, the test source compiled in
	es_ext_lib_test = executable('es_ext_lib_test',
		[ 'es_ext_lib_test.c', 'es_ext_test_plugin.c' ],
		include_directories: include_dirs_es_ext_test,
		link_with: esdm_es_ext_lib.get_static_lib(),
		dependencies: [ dependency('threads'), json_c_dep ],
	)
	test('External ES library', es_ext_lib_test, suite: 'es_ext')

	# The provider programs, against a client of its own with the DTLS of
	# the common library
	es_ext_provider_test = executable('es_ext_provider_test',
		'es_ext_provider_test.c',
		include_directories: include_dirs_es_ext_test,
		dependencies: [ dependencies_client, dependency('threads'),
				json_c_dep ],
		link_with: esdm_common_static_lib,
	)
	test('External ES provider program', es_ext_provider_test,
		args: [ es_ext_test_provider.full_path(),
			es_ext_test_provider_rated.full_path(),
			es_ext_example.full_path(),
			es_ext_example_fifo_provider.full_path(),
			es_ext_example_fifo ],
		depends: [ es_ext_test_provider, es_ext_test_provider_rated,
			   es_ext_example, es_ext_example_fifo_provider ],
		suite: 'es_ext', timeout: 60)

	# The external entropy sources as the esdm-server takes them on its
	# command line. Skipped (77) unless run as root.
	if get_option('es_ext').enabled() and get_option('esdm-server').enabled()
		es_ext_server_test = executable('es_ext_server_test',
			'es_ext_server_test.c',
			include_directories: [ include_dirs_client,
					       include_directories('../common') ],
			dependencies: dependencies_client + [ json_c_dep ],
			link_with: [ esdm_common_static_lib,
				     esdm_rpc_client_lib ],
		)
		test('esdm-server with external entropy sources',
			es_ext_server_test,
			args: [ esdm_server.full_path(),
				es_ext_test_provider.full_path(),
				es_ext_test_provider_rated.full_path() ],
			depends: [ esdm_server, es_ext_test_provider,
				   es_ext_test_provider_rated ],
			suite: 'es_ext', timeout: 120)
	endif

	# esdm-es-pkcs11 against SoftHSM, behind a PKCS#11 module of the test
	# counting the logins - see the file header. The token part is skipped
	# without softhsm2-util on the path.
	if get_option('es_pkcs11').enabled()
		es_pkcs11_shim = shared_module('esdm_es_pkcs11_shim',
			'es_pkcs11_shim.c',
			dependencies: [ dl_dep ],
		)
		es_pkcs11_test = executable('es_pkcs11_test',
			'es_pkcs11_test.c',
			include_directories: include_dirs_es_ext_test,
			dependencies: [ dependencies_client,
					dependency('threads'), json_c_dep ],
			link_with: esdm_common_static_lib,
		)
		test('esdm-es-pkcs11', es_pkcs11_test,
			args: [ esdm_es_pkcs11.full_path(),
				es_pkcs11_shim.full_path() ],
			depends: [ esdm_es_pkcs11, es_pkcs11_shim ],
			suite: 'es_ext', timeout: 120)
	endif
endif

# The source is compiled into its tests, which test the first one
if get_option('es_ext').enabled()
	# The socket source is compiled into the test - see the file header -
	# against the provider server of the library serving the test source.
	if get_option('esdm-es-ext').enabled()
		es_extsock_test = executable('es_extsock_test',
			[ esdm_ipc_ns, 'es_extsock_test.c',
			  'es_ext_test_plugin.c' ],
			dependencies: dependencies_server,
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			link_with: [ esdm_static_lib,
				     esdm_es_ext_lib.get_static_lib() ],
		)
		test('External ES provider socket', es_extsock_test,
			suite: 'es_ext', timeout: 60)

		# The self test of a provider before the initial seeding of
		# esdm_init(), the test source served in process
		es_ext_init_test = executable('es_ext_init_test',
			[ esdm_ipc_ns, 'es_ext_init_test.c',
			  'es_ext_test_plugin.c' ],
			dependencies: dependencies_server,
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			link_with: [ esdm_static_lib,
				     esdm_es_ext_lib.get_static_lib() ],
		)
		test('External ES self test before the initial seeding',
			es_ext_init_test, suite: 'es_ext', timeout: 60)
	endif

	# esdm-es-pkcs11 read by the provider socket source, which is compiled
	# into the test - see the file header
	if get_option('es_pkcs11').enabled()
		es_pkcs11_esdm_test = executable('es_pkcs11_esdm_test',
			[ esdm_ipc_ns, 'es_pkcs11_esdm_test.c' ],
			dependencies: dependencies_server,
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			link_with: esdm_static_lib,
		)
		test('esdm-es-pkcs11 read by the ESDM', es_pkcs11_esdm_test,
			args: [ esdm_es_pkcs11.full_path(),
				es_pkcs11_shim.full_path() ],
			depends: [ esdm_es_pkcs11, es_pkcs11_shim ],
			suite: 'es_ext', timeout: 60)
	endif
endif

# Several sources, compiled into the test - see the file header. Only a build
# with two at least has them.
if get_option('es_ext').enabled() and get_option('esdm-es-ext').enabled() and es_ext_socket_num >= 2
	es_ext_multi_test = executable('es_ext_multi_test',
		[ esdm_ipc_ns, 'es_ext_multi_test.c' ],
		dependencies: dependencies_server,
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
	)
	test('External ES with several sources',
		es_ext_multi_test,
		args: [ es_ext_test_provider.full_path(),
			es_ext_test_providers['_bare'].full_path() ],
		depends: [ es_ext_test_provider,
			   es_ext_test_providers['_bare'] ],
		suite: 'es_ext', timeout: 120)
endif
