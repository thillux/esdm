# Tests of the EGD interface. The client library is exercised against the test
# peer next to them, which can produce the answers a correct server never gives,
# and both sides are exercised together against the esdm-server.
#
# Only the latter needs a server - and thus privileges - so everything else runs
# in an ordinary unprivileged test run as well.
egd_test_peer = files([
	'egd_peer.c'
	])

egd_test_deps = [ dependency('threads') ]

egd_client_test = executable(
		'egd_client_test',
		[ egd_test_peer, 'egd_client_test.c' ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_test_deps,
		link_with: [ esdm_egd_client_lib.get_static_lib() ]
	)

egd_robust_test = executable(
		'egd_robust_test',
		[ egd_test_peer, 'egd_robust_test.c' ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_test_deps,
		link_with: [ esdm_egd_client_lib.get_static_lib() ]
	)

# Several of these wait for answers that never come, so they need more than the
# default timeout - which they must never come close to, as running into it is
# how a wedged client would show up.
test('EGD client library', egd_client_test, timeout: 120)

test('EGD client robustness', egd_robust_test, timeout: 120)

# The client's write(2) and sigtimedwait(2) are wrapped, to close the peer
# right before the write and count the calls - see the test.
egd_client_sigpipe_test = executable(
		'egd_client_sigpipe_test',
		[ 'egd_client_sigpipe_test.c' ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_test_deps,
		link_args: [ '-Wl,--wrap=write', '-Wl,--wrap=sigtimedwait' ],
		link_with: [ esdm_egd_client_lib.get_static_lib() ]
	)

test('EGD client SIGPIPE', egd_client_sigpipe_test)

if get_option('esdm-server').enabled()
	# The server side driven in-process and spoken to in raw protocol
	# bytes. Unlike the test below it needs no daemon and therefore no
	# privileges, and it decides itself when the ESDM turns operational -
	# which is the only way to observe what the blocking read command does
	# while it is not. Its server closes idle connections after a few
	# seconds rather than a minute, so that this can be tested as well -
	# well above anything the other tests leave a connection unused for -
	# and does so whenever a single connection is open: the pressure it
	# otherwise waits for is the connection lifecycle test's to cover.
	egd_server_raw_test = executable(
			'egd_server_raw_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_raw_test.c' ],
			c_args: [
				'-DESDM_EGD_IDLE_TIMEOUT_MS=3000',
				'-DESDM_EGD_IDLE_REAP_CONNECTIONS=1',
			],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server raw protocol', egd_server_raw_test, timeout: 300)

	# The same setup for the end of a connection, the client's and the
	# server's. The insertion command has no response, so the server's call
	# into the auxiliary pool is renamed to a counting wrapper in the test.
	# So are its calls rendering a status report and waiting for the events
	# of a round, which tells the reports rendered per round. Idle
	# connections time out after a second, and the per-UID limit is small
	# enough for the test to run into it.
	egd_server_conn_test = executable(
			'egd_server_conn_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_conn_test.c' ],
			c_args: [
				'-Desdm_pool_insert_aux=test_pool_insert_aux',
				'-Desdm_status=test_status',
				'-Desdm_status_json=test_status_json',
				'-Depoll_wait=test_epoll_wait',
				'-DESDM_EGD_IDLE_TIMEOUT_MS=1000',
				'-DESDM_EGD_MAX_CONNECTIONS_PER_UID=48',
			],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server connection lifecycle', egd_server_conn_test,
		timeout: 300)

	# The same setup with all connection slots taken. The server is cut
	# down to a few slots, more of them per UID than in all - a single UID
	# stands for a user connecting under each UID of its subordinate range
	# - and slots are short from three quarters of them on. Idle
	# connections time out after eight seconds, well above how long the
	# tests not about them take even under a sanitizer: opening all slots
	# and touching all but two of them one after the other took close to
	# three seconds in the TSan build, and the last ones were then closed
	# as idle before their turn. Several UIDs, and the tests needing them,
	# take root. The server's calls into the auxiliary pool, waiting for
	# the events of a round and shutting a connection down are renamed to
	# wrappers in the test, which count the insertions and send one on a
	# connection in the middle of a round or of its closing.
	egd_server_evict_test = executable(
			'egd_server_evict_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_evict_test.c' ],
			c_args: [
				'-DESDM_EGD_MAX_CONNECTIONS=16',
				'-DESDM_EGD_MAX_CONNECTIONS_PER_UID=24',
				'-DESDM_EGD_IDLE_REAP_CONNECTIONS=12',
				'-DESDM_EGD_IDLE_TIMEOUT_MS=8000',
				'-Desdm_pool_insert_aux=test_pool_insert_aux',
				'-Depoll_wait=test_epoll_wait',
				'-Dshutdown=test_shutdown',
			],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server with all slots taken', egd_server_evict_test,
		timeout: 300)

	# The same setup with an operational ESDM, which the Jitter RNG makes
	# it, and prediction resistant requests on many connections.
	egd_server_pr_budget_test = executable(
			'egd_server_pr_budget_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_pr_budget_test.c' ],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server prediction resistance budget',
		egd_server_pr_budget_test, timeout: 300)

	# The same with several workers, one client flooding the prediction
	# resistance DRNG and others asking for a block each. Timed, so not
	# alongside other tests.
	egd_server_pr_fairness_test = executable(
			'egd_server_pr_fairness_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_pr_fairness_test.c' ],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server prediction resistance fairness',
		egd_server_pr_fairness_test, timeout: 120, is_parallel: false)

	# The per-UID connection accounting shared by the RPC and EGD servers,
	# compiled into the test to inspect its table. Needs no server.
	egd_peer_limit_test = executable(
			'egd_peer_limit_test',
			[ 'egd_peer_limit_test.c' ],
			include_directories: include_dirs_server,
			dependencies: egd_test_deps
		)

	test('EGD server peer limit', egd_peer_limit_test)

	egd_server_test = executable(
			'egd_server_test',
			[ 'egd_server_test.c' ],
			include_directories: include_dirs_egd_client,
			dependencies: egd_test_deps,
			link_with: [ esdm_egd_client_lib.get_static_lib() ]
		)

	# Skipped (77) unless it is run as root: the esdm-server refuses to
	# start otherwise. The daemon it starts claims the fixed socket,
	# semaphore and IPC names, so the test puts itself in namespaces of its
	# own - which is what lets it run next to the rest.
	test('EGD server interface', egd_server_test,
		env: [ 'ESDM_SERVER=' + esdm_server.full_path() ],
		timeout: 300)
endif
