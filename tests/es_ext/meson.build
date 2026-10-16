# The external entropy sources: the library they are developed against, the
# sources of the ESDM, and the plugins the tests load - see the file headers.
# The plugins need nothing but the header.
if get_option('esdm-es-ext').enabled() or get_option('es_ext').enabled()
	include_dirs_es_ext_test = [ include_dirs_es_ext,
				     include_directories('../common') ]

	es_ext_test_plugin = shared_module('esdm_es_ext_test_plugin',
		'es_ext_test_plugin.c',
		include_directories: include_dirs_es_ext_test,
		build_by_default: true,
	)

	es_ext_bad_version_plugin = shared_module('esdm_es_ext_bad_version',
		'es_ext_bad_plugin.c',
		c_args: [ '-DES_EXT_BAD_VERSION' ],
		include_directories: include_dirs_es_ext_test,
	)
	es_ext_bad_no_get_plugin = shared_module('esdm_es_ext_bad_no_get',
		'es_ext_bad_plugin.c',
		c_args: [ '-DES_EXT_BAD_NO_GET' ],
		include_directories: include_dirs_es_ext_test,
	)
	es_ext_bad_no_plugin = shared_module('esdm_es_ext_bad_no_plugin',
		'es_ext_bad_plugin.c',
		include_directories: include_dirs_es_ext_test,
	)
	# The example of es-ext/example, reading a device every test system
	# has, so that it is built and run rather than only shipped.
	es_ext_example_plugin = shared_module('esdm_es_ext_example',
		'../../es-ext/example/esdm_es_ext_example.c',
		c_args: [ '-DESDM_ES_EXT_EXAMPLE_DEVICE="/dev/urandom"' ],
		include_directories: include_dirs_es_ext_test,
	)
	es_ext_plugins = [ es_ext_test_plugin, es_ext_bad_version_plugin,
			   es_ext_bad_no_get_plugin, es_ext_bad_no_plugin,
			   es_ext_example_plugin ]
	es_ext_plugin_args = [ es_ext_test_plugin.full_path(),
			       es_ext_bad_version_plugin.full_path(),
			       es_ext_bad_no_get_plugin.full_path(),
			       es_ext_bad_no_plugin.full_path(),
			       es_ext_example_plugin.full_path() ]

	es_ext_proto_test = executable('es_ext_proto_test',
		'es_ext_proto_test.c',
		include_directories: include_dirs_es_ext_test,
	)
	test('External ES protocol', es_ext_proto_test, suite: 'es_ext')
endif

if get_option('esdm-es-ext').enabled()
	es_ext_lib_test = executable('es_ext_lib_test',
		'es_ext_lib_test.c',
		include_directories: include_dirs_es_ext_test,
		link_with: esdm_es_ext_lib.get_static_lib(),
		dependencies: [ dependency('threads'), dl_dep ],
	)
	test('External ES library', es_ext_lib_test,
		args: es_ext_plugin_args, depends: es_ext_plugins,
		suite: 'es_ext')
endif

if get_option('es_ext').enabled()
	es_extlib_test = executable('es_extlib_test',
		[ esdm_ipc_ns, 'es_extlib_test.c' ],
		dependencies: dependencies_server + [ dl_dep ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
	)
	test('External ES plugin library', es_extlib_test,
		args: es_ext_plugin_args, depends: es_ext_plugins,
		suite: 'es_ext')
endif
