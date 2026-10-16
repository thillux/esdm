# Tests of the esdm-server command line and of the PID file it writes.
#
# The daemon is executed rather than linked, because what is under test is what
# a user gets from it: the usage, the version, and what it makes of the options
# before it decides whether it may run at all.
if get_option('esdm-server').enabled()
	server_cli_test = executable(
			'server_cli_test',
			[ 'server_cli_test.c' ],
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
		)

	test('esdm-server command line', server_cli_test,
		args: [ esdm_server.full_path() ])

	# What is left of the PID file once the daemon terminated. Skipped (77)
	# unless it is run as root, as the esdm-server refuses to start
	# otherwise. The daemon claims the fixed socket, semaphore and IPC
	# names, so the test puts itself in namespaces of its own.
	server_pidfile_test = executable(
			'server_pidfile_test',
			[ 'server_pidfile_test.c' ],
		)

	test('esdm-server PID file', server_pidfile_test,
		env: [ 'ESDM_SERVER=' + esdm_server.full_path() ],
		timeout: 180)
endif
