# Every test here drives the ESDM in process and therefore touches the
# machine-global System V names - see tests/test_ipc_ns.c.
esdm_ipc_ns = files('../test_ipc_ns.c')

es_mgr_monitor_tester = executable(
	'es_mgr_monitor_tester',
	[ esdm_ipc_ns, 'es_mgr_monitor_test.c' ],
	dependencies: dependencies_server,
	include_directories: include_dirs_server,
	link_with: esdm_static_lib,
)

test('ES manager monitor', es_mgr_monitor_tester, timeout: 120)

# Whatever entropy sources this build and this machine actually have - the test
# walks the ES manager's table rather than naming any of them, so it needs no
# option guard of its own.
es_seed_cycle_tester = executable(
	'es_seed_cycle_tester',
	[ esdm_ipc_ns, 'es_seed_cycle_test.c' ],
	dependencies: dependencies_server,
	include_directories: include_dirs_server,
	link_with: esdm_static_lib,
)

# Serial: it reports durations, and a duration measured while the rest of the
# suite has the machine is a measure of the suite.
test('ES seed cycle duration', es_seed_cycle_tester,
	timeout: 300,
	is_parallel: false,
	priority: -10)

if get_option('es_jent').enabled()
	es_jent_tester = executable(
		'es_jent_tester',
		[ esdm_ipc_ns, 'es_jent_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG', es_jent_tester, timeout: 300)

	es_jent_init_fail_tester = executable(
		'es_jent_init_fail_tester',
		[ esdm_ipc_ns, 'es_jent_init_fail_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG failing self test', es_jent_init_fail_tester,
	     timeout: 120)

	es_jent_selftest_fail_tester = executable(
		'es_jent_selftest_fail_tester',
		[ esdm_ipc_ns, 'es_jent_selftest_fail_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG failing periodic health test',
	     es_jent_selftest_fail_tester, timeout: 120)

	es_jent_collector_lost_tester = executable(
		'es_jent_collector_lost_tester',
		[ esdm_ipc_ns, 'es_jent_collector_lost_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG collector lost to a failed recovery',
	     es_jent_collector_lost_tester, timeout: 120)
endif

if get_option('es_cpu').enabled()
	es_cpu_tester = executable(
		'es_cpu_tester',
		[ esdm_ipc_ns, 'es_cpu_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES CPU', es_cpu_tester)

	# RDRAND is unreachable through the entropy source on every CPU that has
	# RDSEED, so the two instructions are driven directly - see the file
	# header. Needs no ESDM around it, only the logger the header calls.
	if host_machine.cpu_family() in [ 'x86', 'x86_64' ]
		es_cpu_x86_tester = executable(
			'es_cpu_x86_tester',
			'es_cpu_x86_test.c',
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			dependencies: dependencies_server,
			link_with: esdm_common_static_lib,
		)

		test('ES CPU x86 RDSEED/RDRAND', es_cpu_x86_tester)
	endif

	# The compressing data path is selected by a multiplier that is fixed at
	# build time and is 1 in every configuration this suite is built in, so
	# the entropy source is compiled into the test with the build option
	# raised - see the file header.
	es_cpu_compress_tester = executable(
		'es_cpu_compress_tester',
		[ esdm_ipc_ns, 'es_cpu_compress_test.c' ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server,
		link_with: esdm_static_lib,
	)

	test('ES CPU compressing path', es_cpu_compress_tester)
endif

if get_option('es_kernel').enabled()
	es_krng_tester = executable(
		'es_krng_tester',
		[ esdm_ipc_ns, 'es_krng_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel', es_krng_tester)

	# The interrupt ES is compiled into the test to fake the descriptor of
	# its kernel add-on - see the file header.
	if get_option('es_irq').enabled()
		es_krng_irq_cap_tester = executable(
			'es_krng_irq_cap_tester',
			[ esdm_ipc_ns, 'es_krng_irq_cap_test.c' ],
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			dependencies: dependencies_server,
			link_with: esdm_static_lib,
		)

		test('ES Kernel capped while the interrupt add-on is present',
		     es_krng_irq_cap_tester)
	endif
endif

if get_option('es_sched').enabled()
	es_sched_tester = executable(
		'es_sched_tester',
		[ esdm_ipc_ns, 'es_sched_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Scheduler', es_sched_tester, timeout: 70)
endif

if get_option('es_irq').enabled()
	es_irq_tester = executable(
		'es_irq_tester',
		[ esdm_ipc_ns, 'es_irq_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	# The interrupt generator sleeps 5000 times per round, so the wall clock
	# is dominated by the rounds rather than by the work.
	test('ES Interrupt', es_irq_tester, timeout: 300)
endif

# The interrupt and the scheduler source compiled into the test, which fills
# their block cache by hand - see the file header. No kernel support needed.
foreach es_reset : [ [ 'es_irq', 'interrupt', [] ],
		     [ 'es_sched', 'scheduler', [ '-DTEST_ES_SCHED' ] ] ]
	if get_option(es_reset[0]).enabled()
		es_reset_tester = executable(
			es_reset[0] + '_cache_reset_tester',
			[ 'es_kernel_cache_reset_test.c' ],
			c_args: es_reset[2],
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			dependencies: dependencies_server,
			link_with: esdm_static_lib,
		)

		test('ES ' + es_reset[1] + ' cache reset', es_reset_tester)
	endif
endforeach

# The following hardware/service-backed sources may be absent on the test
# machine; their tests are structural / graceful-absence checks (see the file
# headers) and pass whether or not the device is present.
if get_option('es_hwrand').enabled()
	es_hwrand_tester = executable(
		'es_hwrand_tester',
		[ esdm_ipc_ns, 'es_hwrand_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Linux HW Random', es_hwrand_tester)
endif

if get_option('es_tpm2').enabled()
	es_tpm2_tester = executable(
		'es_tpm2_tester',
		[ esdm_ipc_ns, 'es_tpm2_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	# With a TPM behind it the test drives the device itself, including a
	# full fill of the block cache - one command exchange per block, and a
	# software TPM in an emulated machine is not quick about them.
	test('ES TPM 2.0', es_tpm2_tester, timeout: 120)

	# The source is compiled into the test, with a file standing in for
	# the device - see the file header.
	es_tpm2_reopen_tester = executable(
		'es_tpm2_reopen_tester',
		[ esdm_ipc_ns, 'es_tpm2_reopen_test.c' ],
		dependencies: dependencies_server,
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
	)
	test('ES TPM 2.0 reopen', es_tpm2_reopen_tester)

	# The source is compiled into the test as well, talking to a TPM
	# simulated on a socket pair - see the file header.
	es_tpm2_cache_tester = executable(
		'es_tpm2_cache_tester',
		[ esdm_ipc_ns, 'es_tpm2_cache_test.c' ],
		dependencies: dependencies_server,
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
	)
	test('ES TPM 2.0 cache against self test and PR', es_tpm2_cache_tester)
endif


if get_option('es_sched_ebpf').enabled()
	es_sched_ebpf_tester = executable(
		'es_sched_ebpf_tester',
		[ esdm_ipc_ns, 'es_sched_ebpf_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Scheduler eBPF', es_sched_ebpf_tester, timeout: 120)
endif

if get_option('es_irq_ebpf').enabled()
	es_irq_ebpf_tester = executable(
		'es_irq_ebpf_tester',
		[ esdm_ipc_ns, 'es_irq_ebpf_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Interrupt eBPF', es_irq_ebpf_tester, timeout: 120)
endif

if get_option('es_pkcs11').enabled()
	es_pkcs11_tester = executable(
		'es_pkcs11_tester',
		[ esdm_ipc_ns, 'es_pkcs11_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)
	test('ES PKCS11', es_pkcs11_tester)

	# The test above passes with the source switched off for want of a
	# token, so it never reaches the half that matters. SoftHSM is a
	# PKCS#11 module that needs no hardware, so when the build points at
	# one this test creates a token and drives the source against it for
	# real. It skips at runtime if softhsm2-util is not installed.
	if get_option('es_pkcs11_module_path') != ''
		es_pkcs11_softhsm_tester = executable(
			'es_pkcs11_softhsm_tester',
			[ esdm_ipc_ns, 'es_pkcs11_softhsm_test.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
		test('ES PKCS11 with SoftHSM', es_pkcs11_softhsm_tester,
			timeout: 120)
	endif
endif

# The health tests the eBPF programs run are plain C, which the test compiles
# in - see the file header. It needs neither libbpf nor eBPF support, so it is
# built whether or not an eBPF entropy source is.
es_ebpf_health_startup_tester = executable(
	'es_ebpf_health_startup_tester',
	'es_ebpf_health_startup_test.c',
	include_directories: [ include_dirs_server,
			       include_directories('../common') ],
)

test('ES eBPF health startup after a failure', es_ebpf_health_startup_tester)

if get_option('es_sched_ebpf').enabled() or get_option('es_irq_ebpf').enabled()
	es_ebpf_health_tester = executable(
		'es_ebpf_health_tester',
		[ esdm_ipc_ns, 'es_ebpf_health_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES eBPF health cutoffs', es_ebpf_health_tester)

	# The conditioning pool is internal to the glue, which the test
	# compiles in - see the file header.
	es_ebpf_pool_tester = executable(
		'es_ebpf_pool_tester',
		[ esdm_ipc_ns, 'es_ebpf_pool_test.c' ],
		dependencies: dependencies_server,
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
	)

	test('ES eBPF conditioning pool hash failure', es_ebpf_pool_tester)
endif

if get_option('es_jent_kernel').enabled()
	es_jent_kernel_tester = executable(
		'es_jent_kernel_tester',
		[ esdm_ipc_ns, 'es_jent_kernel_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel Jitter RNG', es_jent_kernel_tester)
endif
