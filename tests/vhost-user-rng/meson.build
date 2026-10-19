if get_option('vhost-user-rng').enabled()
	vhost_user_rng_test_inc = [
		include_dirs_client,
		include_directories('../../frontends/vhost-user-rng'),
		include_directories('../rpc_client'),
	]

	# The guest memory table on its own - needs nothing but memfds.
	vhost_user_mem_test = executable('vhost_user_mem_test',
			[ 'vhost_user_mem_test.c' ],
			include_directories: vhost_user_rng_test_inc,
			dependencies: [ dependencies_client ],
			link_with: [ vhost_user_rng_core_lib,
				     esdm_common_static_lib ],
		)

	test('vhost-user RNG guest memory table', vhost_user_mem_test,
		suite: 'vhost-user-rng')

	# The daemon driven by a front-end of the test, with a stand-in ESDM
	# on the unprivileged socket of the test mode - so nothing else may run
	# alongside, and without the test mode the tests skip.
	vhost_user_rng_test = executable('vhost_user_rng_test',
			[ 'vhost_user_rng_test.c', 'vu_frontend.c',
			  'vu_standin.c', '../rpc_client/env.c' ],
			include_directories: vhost_user_rng_test_inc,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib ],
		)

	foreach group : [ 'protocol', 'ring', 'hostile', 'lifecycle', 'options' ]
		test('vhost-user RNG ' + group, vhost_user_rng_test,
			args: [ group ],
			env: [ 'ESDM_VHOST_USER_RNG=' + esdm_vhost_user_rng.full_path() ],
			depends: [ esdm_vhost_user_rng ],
			suite: 'vhost-user-rng',
			is_parallel: false,
			timeout: 180)
	endforeach

	# The daemon serving from an esdm-server of the test's own - which has
	# to start as root, so the test skips otherwise.
	if get_option('esdm-server').enabled()
		test('vhost-user RNG with the ESDM', vhost_user_rng_test,
			args: [ 'esdm' ],
			env: [ 'ESDM_VHOST_USER_RNG=' + esdm_vhost_user_rng.full_path(),
			       'ESDM_SERVER=' + esdm_server.full_path() ],
			depends: [ esdm_vhost_user_rng, esdm_server ],
			suite: 'vhost-user-rng',
			timeout: 300)
	endif
endif
