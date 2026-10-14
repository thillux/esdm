if get_option('esdm-server').enabled()
	esdm_tester_common = files([
		'env.c'
		])

	rpc_get_random_bytes_full_test = executable(
			'rpc_get_random_bytes_full_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_full_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_pr_test = executable(
			'rpc_get_random_bytes_pr_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_pr_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_pr_nonblock_test = executable(
			'rpc_get_random_bytes_pr_nonblock_test',
			[ esdm_tester_common,
			  'rpc_get_random_bytes_pr_nonblock_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_eagain_test = executable(
			'rpc_get_random_bytes_eagain_test',
			[ 'rpc_get_random_bytes_eagain_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_fini_race_test = executable(
			'rpc_fini_race_test',
			[ 'rpc_fini_race_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_client_blocking_test = executable(
			'rpc_client_blocking_test',
			[ 'rpc_client_blocking_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_priv_interrupt_test = executable(
			'rpc_priv_interrupt_test',
			[ 'rpc_priv_interrupt_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_small_stack_test = executable(
			'rpc_small_stack_test',
			[ 'rpc_small_stack_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_connect_deadline_test = executable(
			'rpc_connect_deadline_test',
			[ 'rpc_connect_deadline_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_server_slow_reader_test = executable(
			'rpc_server_slow_reader_test',
			[ 'rpc_server_slow_reader_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_pr_request_size_test = executable(
			'rpc_pr_request_size_test',
			[ esdm_tester_common, 'rpc_pr_request_size_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib ]
		)

	# This is just a helper for debugging - no real test
	esdm_rpc_invoker = executable(
			'esdm_rpc_invoker',
			[ esdm_tester_common, 'esdm_rpc_invoker.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_test = executable(
			'rpc_get_random_bytes_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	# One test over the whole client API: most of its calls are a file each
	# and had never been executed.
	rpc_api_test = executable(
			'rpc_api_test',
			[ esdm_tester_common, 'rpc_api_test.c' ],
			include_directories: [ include_dirs_client,
					       include_dirs_server,
					       include_directories('../common') ],
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_seed_test = executable(
			'rpc_get_seed_test',
			[ esdm_tester_common, 'rpc_get_seed_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_status_test = executable(
			'rpc_status_test',
			[ esdm_tester_common, 'rpc_status_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client, json_c_dep ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_ent_lvl_test = executable(
			'rpc_ent_lvl_test',
			[ esdm_tester_common, 'rpc_ent_lvl.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_seed_lvl_test = executable(
			'rpc_seed_lvl_test',
			[ esdm_tester_common, 'rpc_seed_lvl.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	#	libesdm-getrandom: esdm_getrandom_lib
	tester_esdm_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		]

	# This and get_random_bytes_test below draw some 16 MiB each, in
	# requests of up to 64 KiB. With the reseeding caps of an sp80090c,
	# fips140 or ais2031_drg4 build, the DRNG reseeds every few KiB, each
	# time waiting for a synchronous Jitter RNG collection - 20 to 30
	# seconds on a lightly loaded machine, which leaves the default 30
	# seconds no room for a busier one.
	test('RPC call get_random_bytes_full_test', rpc_get_random_bytes_full_test,
		env: [ tester_esdm_env ], timeout: 300)

	test('RPC call get_random_bytes_pr_test', rpc_get_random_bytes_pr_test,
		env: [ tester_esdm_env ])

	test('RPC call get_random_bytes_pr_nonblock_test',
		rpc_get_random_bytes_pr_nonblock_test, env: [ tester_esdm_env ])

	test('RPC call get_random_bytes_test', rpc_get_random_bytes_test,
		env: [ tester_esdm_env ], timeout: 300)

	# A stand-in server on the unprivileged socket every RPC test uses, so
	# nothing else may run alongside.
	test('RPC call get_random_bytes retries on EAGAIN',
		rpc_get_random_bytes_eagain_test, is_parallel: false)

	# Needs no server: only the thread creation is tested.
	test('RPC client leaves small thread stacks usable',
		rpc_small_stack_test)

	# The same stand-in, answering calls while the client is set up and
	# torn down under them.
	test('RPC client torn down during calls', rpc_fini_race_test,
		is_parallel: false)

	# Also a stand-in server on the unprivileged socket.
	test('RPC client does not stall on calls waiting for the seeding',
		rpc_client_blocking_test, is_parallel: false, timeout: 60)

	# A stand-in server on the privileged socket.
	test('RPC client does not resend an interrupted privileged call',
		rpc_priv_interrupt_test, is_parallel: false)

	# Binds the unprivileged socket every RPC test uses without listening.
	test('RPC client gives up connecting at its deadline',
		rpc_connect_deadline_test, is_parallel: false)

	# Times the server under load - not alongside other tests.
	test('RPC server is not stalled by clients that do not read',
		rpc_server_slow_reader_test, env: [ tester_esdm_env ],
		is_parallel: false, timeout: 120)

	test('RPC call get_random_bytes_pr beyond its request size',
		rpc_pr_request_size_test, env: [ tester_esdm_env ])

	test('RPC call get_seed_test', rpc_get_seed_test,
		env: [ tester_esdm_env ])

	test('RPC call status_test', rpc_status_test,
		env: [ tester_esdm_env ])

	test('RPC call ent_lvl_test', rpc_ent_lvl_test,
		env: [ tester_esdm_env ])

	test('RPC call seed_lvl_test', rpc_seed_lvl_test,
		env: [ tester_esdm_env ])

	# Sweeps every client wrapper in one server life cycle, hence the
	# larger timeout.
	test('RPC call whole client API', rpc_api_test,
		env: [ tester_esdm_env ], timeout: 300)
endif
