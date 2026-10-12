sha256_tester = executable(
		'sha256_tester',
		[ 'sha256_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

sha512_tester = executable(
		'sha512_tester',
		[ 'sha512_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

hmac_sha2_256_tester = executable(
		'hmac_sha2_256_tester',
		[ 'hmac_sha2_256_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

hmac_sha2_512_tester = executable(
		'hmac_sha2_512_tester',
		[ 'hmac_sha2_512_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

# The built-in SHA-3 is only part of the library when it is the conditioning
# hash (hash_sha3_512). It is tested in every build all the same, compiled into
# the test where the library does not carry it.
sha3_tester_src = [ 'sha3_tester.c' ]
if not get_option('hash_sha3_512').enabled()
	sha3_tester_src += files('../../crypto/sha3.c')
endif

sha3_tester = executable(
		'sha3_tester',
		sha3_tester_src,
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

test('SHA256', sha256_tester)
test('SHA512', sha512_tester)
test('SHA3', sha3_tester)

test('HMAC SHA256', hmac_sha2_256_tester)
test('HMAC SHA512', hmac_sha2_512_tester)

if get_option('drng_hash_drbg').enabled()
	hash_drbg_tester = executable(
			'hash_drbg_tester',
			[ 'hash_drbg_tester.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
	test('Hash DRBG SHA512', hash_drbg_tester)

	drbg_healthcheck_tester = executable(
			'drbg_healthcheck_tester',
			[ 'drbg_healthcheck_tester.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
	test('DRBG health check', drbg_healthcheck_tester)
endif

if get_option('crypto_backend') == 'leancrypto'
	leancrypto_drbg_tester = executable(
			'leancrypto_drbg_tester',
			[ 'leancrypto_drbg_tester.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
	test('leancrypto DRBG', leancrypto_drbg_tester)
endif
