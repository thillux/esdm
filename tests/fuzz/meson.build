# Fuzz harnesses for the RPC interfaces. Each is built twice: as a libFuzzer
# binary, and with the seed-replaying driver in fuzz_driver.c, which needs no
# fuzzing engine and runs in the ordinary test suite.

fuzz_cc = meson.get_compiler('c')

# libFuzzer defines main() and calls into the harness - a link test needs the
# entry point the engine looks for.
fuzz_engine_probe = '''
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	(void)data;
	(void)size;
	return 0;
}
'''

have_libfuzzer = fuzz_cc.links(fuzz_engine_probe,
			       args: [ '-fsanitize=fuzzer' ],
			       name: 'libFuzzer')

if not have_libfuzzer
	message('No libFuzzer in this compiler - the fuzz harnesses are built with the replay driver only')
endif

# protobuf-c calls a closure of a generic type through the type of the message
# it carries, which the indirect call check of clang 17+ reports on every call.
# Turn that one check off where the compiler knows the option.
fuzz_c_args = [ ]
if fuzz_cc.has_argument('-fno-sanitize=function')
	fuzz_c_args += [ '-fno-sanitize=function' ]
endif

fuzz_targets = [
	# The requests the server takes off its two sockets, served by the whole
	# server built from its sources - the fuzzer is guided by what the ESDM
	# does with a request, not only by what the RPC layer does.
	{
		'name': 'rpc_request',
		'sources': [ common_src, crypto_src, esdm_src,
			     service_rpc_src, server_rpc_src, egd_server_src,
			     files('rpc_request_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
	},
	# The responses a client parses. The client stack only, no server and
	# no ESDM - the bytes come from the harness.
	{
		'name': 'rpc_response',
		'sources': [ service_rpc_src, client_rpc_src,
			     files('rpc_response_fuzz.c') ],
		'include': [ include_dirs_client, include_dirs_server ],
		'deps': dependencies_client,
		'link': [ esdm_common_static_lib ],
	},
	# The server as a client reaches it: the client library on one side,
	# the server's accept loop and worker threads on the other, both in
	# this process. One input is a script of client calls.
	{
		'name': 'rpc_client',
		'sources': [ common_src, crypto_src, esdm_src, service_rpc_src,
			     server_rpc_src, egd_server_src, client_rpc_src,
			     files('rpc_client_fuzz.c') ],
		'include': [ include_dirs_server, include_dirs_client ],
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
		'parallel': false,
		'timeout': 300,
	},
	# The EGD compatibility interface of the server: a byte stream with no
	# framing above the commands themselves, so an input is the stream and
	# the reads it arrives in.
	{
		'name': 'egd',
		# server_rpc_src for the stale socket removal the EGD server
		# shares with the RPC one - none of it is reached from here.
		'sources': [ common_src, crypto_src, esdm_src, service_rpc_src,
			     server_rpc_src, egd_server_src,
			     files('egd_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
	},
	# The library itself, called the way a program linking it does. No RPC
	# at all: one input is a sequence of API calls, so what is fuzzed is
	# also the state they share.
	{
		'name': 'esdm_lib',
		'sources': [ common_src, crypto_src, esdm_src,
			     files('esdm_lib_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_esdm_lib,
		'link': [ ],
	},
	# The EGD client library, the other side of the socket the EGD harness
	# above serves. No ESDM and no server: the answers come from the
	# harness, which is the impostor the client is talking to.
	{
		'name': 'egd_client',
		'sources': [ egd_client_src, files('egd_client_fuzz.c') ],
		'include': include_dirs_egd_client,
		'deps': [ dependency('threads') ],
		'link': [ esdm_common_static_lib ],
	},
	# The wire codec under both of them, called directly: no sockets, no
	# ESDM, and therefore the harness that gets through the most inputs.
	{
		'name': 'rpc_protocol',
		'sources': [ service_rpc_src, files('rpc_protocol_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server,
		'link': [ esdm_common_static_lib ],
	},
]

# The OpenSSL RAND providers. Each shipped provider module is a harness of its
# own: they differ in the interface they reach the ESDM through, in whether
# every request is routed to the prediction resistance generator, and in the
# table of algorithms they offer - all three of which are what the harness
# looks at.
if get_option('openssl-rand-provider').enabled()
	openssl_prov_dir = include_directories('../../frontends/openssl-provider')

	# The RPC based providers share their whole implementation; only the
	# algorithm table differs between them.
	openssl_prov_rpc_src = [
		common_src, crypto_src, esdm_src, service_rpc_src,
		server_rpc_src, egd_server_src, client_rpc_src,
		files('../../frontends/openssl-provider/common.c'),
		files('../../frontends/openssl-provider/prov_error.c'),
		files('ossl_prov_fuzz.c'), files('ossl_rpc_prov_backend.c'),
	]
	openssl_prov_rpc_include = [ include_dirs_server, include_dirs_client,
				     openssl_prov_dir ]
	openssl_prov_rpc_deps = dependencies_server + dependencies_esdm_lib + \
				[ openssl_dep ]

	# The EGD based one needs neither the RPC client nor the ESDM: its peer
	# is a socket, and the harness is what sits behind it.
	openssl_prov_egd_src = [
		egd_client_src,
		files('../../frontends/openssl-provider/egd-provider.c'),
		files('../../frontends/openssl-provider/prov_error.c'),
		files('ossl_prov_fuzz.c'), files('ossl_egd_prov_backend.c'),
	]
	openssl_prov_egd_include = [ include_dirs_egd_client,
				     openssl_prov_dir ]
	openssl_prov_egd_deps = [ openssl_dep, dependency('threads') ]

	fuzz_targets += [
		# libesdm-rng-provider: all four RAND algorithms, over the RPC
		# interface, honoring the prediction resistance flag per call.
		{
			'name': 'ossl_rng_prov',
			'sources': openssl_prov_rpc_src + \
				   files('../../frontends/openssl-provider/rng-provider.c'),
			'include': openssl_prov_rpc_include,
			'deps': openssl_prov_rpc_deps,
			'link': [ ],
			'c_args': [ ],
			'parallel': false,
			'timeout': 300,
		},
		# libesdm-rng-provider-pr: the same, with every request routed
		# to the prediction resistance generator whatever the caller
		# asked for.
		{
			'name': 'ossl_rng_prov_pr',
			'sources': openssl_prov_rpc_src + \
				   files('../../frontends/openssl-provider/rng-provider.c'),
			'include': openssl_prov_rpc_include,
			'deps': openssl_prov_rpc_deps,
			'link': [ ],
			'c_args': [ '-DESDM_OSSL_PROV_FORCE_PR=1',
				    '-DESDM_PROV_NAME="ESDM RNG Provider (PR)"' ],
			'parallel': false,
			'timeout': 300,
		},
		# libesdm-seed-src-provider: the same implementation offering
		# SEED-SRC alone, which is what the algorithm query hands back.
		{
			'name': 'ossl_seed_src_prov',
			'sources': openssl_prov_rpc_src + \
				   files('../../frontends/openssl-provider/seed-src-provider.c'),
			'include': openssl_prov_rpc_include,
			'deps': openssl_prov_rpc_deps,
			'link': [ ],
			'c_args': [ ],
			'parallel': false,
			'timeout': 300,
		},
		# libesdm-egd-provider: the EGD socket instead of the RPC
		# interface, and a peer whose answers the fuzzer writes. This
		# one has to refuse a request asking for prediction resistance.
		{
			'name': 'ossl_egd_prov',
			'sources': openssl_prov_egd_src,
			'include': openssl_prov_egd_include,
			'deps': openssl_prov_egd_deps,
			'link': [ esdm_common_static_lib ],
			'c_args': [ '-DESDM_FUZZ_PROV_EGD=1' ],
		},
		# libesdm-egd-provider-pr: bound to the socket of the
		# prediction resistance generator, so it accepts what its
		# sibling refuses.
		{
			'name': 'ossl_egd_prov_pr',
			'sources': openssl_prov_egd_src,
			'include': openssl_prov_egd_include,
			'deps': openssl_prov_egd_deps,
			'link': [ esdm_common_static_lib ],
			'c_args': [ '-DESDM_FUZZ_PROV_EGD=1',
				    '-DESDM_EGD_PROV_FORCE_PR=1' ],
		},
	]
endif

# The same request path as the first harness, driven by several threads at
# once: what a fuzzer cannot reach on its own, as it feeds one input at a time.
rpc_stress_test = executable(
		'rpc_stress_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, files('rpc_stress.c') ],
		include_directories: include_dirs_server,
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC request path under concurrent load', rpc_stress_test, timeout: 300)

# The answers the server gives where it cannot give the one asked for, through
# the same request path as the first harness.
rpc_server_test = executable(
		'rpc_server_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, files('rpc_server_test.c') ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC server failure answers', rpc_server_test)

# How the server's accept loop and workers handle their connections, serving a
# stand-in service on sockets of the test's own.
rpc_server_conn_test = executable(
		'rpc_server_conn_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, files('rpc_server_conn_test.c') ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC server connection handling', rpc_server_conn_test, timeout: 60)

# The opportunistic DTLS of the RPC connections: the client library of the test
# against the server's accept loop and workers serving stand-in services,
# through a relay on the sockets the client connects to - which are fixed at
# build time, hence alone. Without DTLS built, what is left is the server
# refusing it.
rpc_dtls_test = executable(
		'rpc_dtls_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, client_rpc_src,
		  files('rpc_dtls_test.c') ],
		include_directories: [ include_dirs_server, include_dirs_client,
				       include_directories('../common') ],
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC connections with DTLS', rpc_dtls_test,
	timeout: 120,
	is_parallel: false)

# libesdm_getrandom preloaded into a client whose DTLS handshake asks it for
# random numbers, against rpc_dtls_test serving in a process of its own.
if get_option('linux-getrandom').enabled()
	rpc_dtls_getrandom_test = executable(
			'rpc_dtls_getrandom_test',
			[ files('rpc_dtls_getrandom_test.c') ],
			include_directories: [ include_dirs_client,
					       include_directories('../common') ],
			dependencies: dependencies_client,
		)

	test('RPC connections with DTLS in libesdm_getrandom',
		rpc_dtls_getrandom_test,
		env: [ 'ESDM_RPC_DTLS_SERVER=' + rpc_dtls_test.full_path(),
		       'LD_PRELOAD=' + esdm_getrandom_lib.full_path(),
		       # See tester_getrandom_env in tests/getrandom
		       'ASAN_OPTIONS=halt_on_error=1:abort_on_error=1' +
				':print_summary=1:verify_asan_link_order=0' ],
		depends: [ rpc_dtls_test ],
		timeout: 120,
		is_parallel: false)
endif

# Prediction resistant and seed requests flooding one worker, served by the
# real unprivileged service and an ESDM of the test's own - in an IPC namespace
# of its own, as the ESDM claims the fixed status segment names.
rpc_server_pr_budget_test = executable(
		'rpc_server_pr_budget_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, files('../test_ipc_ns.c'),
		  files('rpc_server_pr_budget_test.c') ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC server budget of prediction resistance and seeds',
	rpc_server_pr_budget_test,
	timeout: 120)

foreach fuzz_target : fuzz_targets
	target_c_args = fuzz_c_args + fuzz_target.get('c_args', [ ])

	fuzz_replay = executable(
			fuzz_target['name'] + '_fuzz_replay',
			[ fuzz_target['sources'], files('fuzz_driver.c') ],
			include_directories: fuzz_target['include'],
			dependencies: fuzz_target['deps'],
			link_with: fuzz_target['link'],
			c_args: target_c_args,
		)

	# The seeds are the harness' regression corpus. A harness bringing up
	# the RPC server binds its two sockets, whose paths are fixed at build
	# time, so those run alone.
	test('Fuzz seeds - ' + fuzz_target['name'], fuzz_replay,
		timeout: fuzz_target.get('timeout', 120),
		is_parallel: fuzz_target.get('parallel', true))

	if have_libfuzzer
		executable(
			fuzz_target['name'] + '_fuzz',
			fuzz_target['sources'],
			include_directories: fuzz_target['include'],
			dependencies: fuzz_target['deps'],
			link_with: fuzz_target['link'],
			c_args: target_c_args + [ '-fsanitize=fuzzer' ],
			link_args: [ '-fsanitize=fuzzer' ],
		)
	endif
endforeach
