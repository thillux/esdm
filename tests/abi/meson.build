# The exported API of every installed shared library against its installed
# headers - see check_exports.py. What a library exports is set by its version
# script, which is maintained by hand next to the header: a function declared
# but missing from the script is local to the library and cannot be linked
# against, which nothing else in the test suite notices, as the tests link the
# static libraries or the sources themselves.

nm = find_program('nm', required: false)
python = import('python').find_installation()

if nm.found() and get_option('default_library') != 'static'
	check_exports = files('check_exports.py')

	# library() rather than both_libraries() for these, so what it returns
	# depends on default_library.
	if get_option('default_library') == 'both'
		abi_esdm_lib = esdm_lib.get_shared_lib()
	else
		abi_esdm_lib = esdm_lib
	endif

	abi_libs = {
		'libesdm': [ abi_esdm_lib,
			     files('../../esdm/esdm.h',
				   '../../esdm/esdm_config.h') ],
		'libesdm_rpc_client': [ esdm_rpc_client_lib.get_shared_lib(),
					files('../../service-rpc/client/esdm_rpc_client.h') ],
		'libesdm_egd_client': [ esdm_egd_client_lib.get_shared_lib(),
					files('../../service-egd/client/esdm_egd_client.h') ],
	}
	if get_option('esdm-es-ext').enabled()
		abi_libs += {
			'libesdm_es_ext': [ esdm_es_ext_lib.get_shared_lib(),
					    files('../../es-ext/esdm_es_ext.h') ],
		}
	endif
	if get_option('esdm-aux-client').enabled()
		abi_libs += {
			'libesdm_aux_client': [ esdm_aux_client_lib.get_shared_lib(),
						files('../../frontends/aux-client/esdm_aux_client.h') ],
		}
	endif

	# Not API, but every function of the thread pool has to be exported -
	# see the threading section of esdm/version.lds.
	abi_private_headers = {
		'libesdm': files('../../common/threading_support.h'),
	}

	foreach name, lib_headers : abi_libs
		args = [ check_exports, '--nm', nm.full_path(), '--lib', lib_headers[0] ]
		foreach header : lib_headers[1]
			args += [ '--header', header ]
		endforeach
		foreach header : abi_private_headers.get(name, [])
			args += [ '--private-header', header ]
		endforeach
		test('Exported API of ' + name, python,
			args: args,
			depends: lib_headers[0],
			suite: 'abi')
	endforeach

	# The OpenSSL providers have no header: OpenSSL looks up the entry point
	# and nothing else, and the version script hides the rest.
	if get_option('openssl-rand-provider').enabled()
		foreach provider : [ esdm_openssl_rng_provider_lib,
				     esdm_openssl_rng_provider_pr_lib,
				     esdm_openssl_egd_provider_lib,
				     esdm_openssl_egd_provider_pr_lib,
				     esdm_openssl_seed_src_provider_lib ]
			abi_provider = provider
			if get_option('default_library') == 'both'
				abi_provider = provider.get_shared_lib()
			endif
			test('Exported symbols of ' + abi_provider.name(), python,
				args: [ check_exports, '--nm', nm.full_path(),
					'--lib', abi_provider,
					'--exactly', 'OSSL_provider_init' ],
				depends: abi_provider,
				suite: 'abi')
		endforeach
	endif
endif
