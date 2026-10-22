if get_option('esdm-server').enabled()
	# The entropy the seeder credits an insertion with, decided from the
	# status of the ESDM. The translation unit is compiled into the test,
	# with its main() renamed out of the way, so this needs neither a
	# server nor the kernel.
	kernel_seeder_credit_test = executable(
		'kernel_seeder_credit_test',
		[ 'kernel_seeder_credit_test.c' ],
		c_args: [ '-Dmain=esdm_kernel_seeder_main_unused' ],
		include_directories: [
			include_dirs_client,
			include_directories('../../frontends/kernel-seeder'),
			include_directories('../common') ],
		dependencies: [ dependencies_client, json_c_dep ],
		link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ],
	)

	test('Kernel entropy feeder credit', kernel_seeder_credit_test)

	kernel_seeder_tester = executable(
		'kernel_seeder_tester',
		[ 'kernel_seeder_test.c' ],
		include_directories: include_dirs_client,
	)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-kernel-seeder: esdm_kernel_seeder
	tester_kernel_seeder_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_KERNEL_SEEDER=' + esdm_kernel_seeder.full_path()
		]

	# The end-to-end part of this test spawns an ESDM server and inserts
	# entropy into the running kernel - keep it away from everything else.
	test('Kernel entropy feeder', kernel_seeder_tester,
		env: [ tester_kernel_seeder_env ],
		timeout: 180,
		is_parallel: false)
endif
