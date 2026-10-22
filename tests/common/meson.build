# Tests of the common/ helper code.
#
# These only need the code in common/ itself, so they link against
# esdm_common_static_lib rather than the full ESDM library and run without any
# privileges, a server or an initialized DRNG.

common_test_deps = [ dependencies_client, dependency('threads') ]

binhexbin_test = executable(
		'binhexbin_test',
		[ 'binhexbin_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

bitops_test = executable(
		'bitops_test',
		[ 'bitops_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

# conv_be_le.h resolves the byte swaps to compiler builtins unless
# CONVERSION_TEST is defined. Build the same test both ways so the header's own
# rotation-based fallback - what a toolchain without the builtins would use -
# is compiled and executed as well.
conv_be_le_test = executable(
		'conv_be_le_test',
		[ 'conv_be_le_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

conv_be_le_sw_test = executable(
		'conv_be_le_sw_test',
		[ 'conv_be_le_test.c' ],
		c_args: [ '-DCONVERSION_TEST' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

buffer_test = executable(
		'buffer_test',
		[ 'buffer_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

esdm_logger_test = executable(
		'esdm_logger_test',
		[ 'esdm_logger_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

linux_support_test = executable(
		'linux_support_test',
		[ 'linux_support_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

helper_test = executable(
		'helper_test',
		[ 'helper_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

selftest_kat_test = executable(
		'selftest_kat_test',
		[ 'selftest_kat_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

os_random_test = executable(
		'os_random_test',
		[ 'os_random_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

xoshiro_test = executable(
		'xoshiro_test',
		[ 'xoshiro_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

threading_support_test = executable(
		'threading_support_test',
		[ 'threading_support_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

queue_test = executable(
		'queue_test',
		[ 'queue_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

if get_option('testmode').enabled()
	# The shared memory segment is a system wide singleton keyed by a fixed
	# ftok() value, so this would otherwise run next to everything else that
	# attaches to it - which is every test mode ESDM on the machine. An IPC
	# namespace of its own keeps the segment to itself; see
	# tests/test_ipc_ns.c.
	test_pertubation_test = executable(
			'test_pertubation_test',
			[ files('../test_ipc_ns.c'), 'test_pertubation_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	test('common test perturbation', test_pertubation_test)
endif

# Both of these are only compiled into common_src when their option is set.
if get_option('systemd').enabled()
	systemd_support_test = executable(
			'systemd_support_test',
			[ 'systemd_support_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	test('common systemd support', systemd_support_test)
endif

if get_option('fips140')
	fips_integrity_test = executable(
			'fips_integrity_test',
			[ 'fips_integrity_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	test('common FIPS integrity check', fips_integrity_test)
endif

test('common hex/bin conversion', binhexbin_test)
test('common bit operations', bitops_test)
test('common endianness conversion', conv_be_le_test)
test('common endianness conversion - software byte swap', conv_be_le_sw_test)
test('common buffer handling', buffer_test)
test('common logger', esdm_logger_test)
test('common helper', helper_test)
# The supervisor's children belong to the PID namespace whose init it has
# reaped by its exit, so LeakSanitizer cannot fork its tracer there and aborts.
test('common Linux support', linux_support_test,
	env: [ 'ASAN_OPTIONS=halt_on_error=1:abort_on_error=1' +
		':print_summary=1:detect_leaks=0' ])
test('common known answer test comparison', selftest_kat_test)
test('common operating system random numbers', os_random_test)
test('common xoshiro256++ PRNG', xoshiro_test)
test('common wait queue wakeup', queue_test)

# The threading test occupies an entire thread group at once and waits for
# signals to be delivered, so it neither shares the machine well nor finishes
# within the default timeout on a loaded builder.
test('common threading support', threading_support_test,
	timeout: 120,
	is_parallel: false)

# The DTLS of the connections, by the TLS stack of the crypto backend - see
# common/tls/esdm_dtls.h. Skips (77) in a build without DTLS.
esdm_dtls_test = executable(
		'esdm_dtls_test',
		[ 'esdm_dtls_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)
test('DTLS of the connections', esdm_dtls_test, timeout: 60)

# The same, released at the exit of the process by a handler registered before
# the TLS stack set itself up, as OpenSSL registers its cleanup. Skips (77) in a
# build without DTLS.
esdm_dtls_exit_test = executable(
		'esdm_dtls_exit_test',
		[ 'esdm_dtls_exit_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)
test('DTLS of the connections released at the exit', esdm_dtls_exit_test,
	timeout: 60)
