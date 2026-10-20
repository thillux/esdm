# The sources of every build - the optional ones follow below
esdm_src = files([
	'crypto/esdm_xdrbg.c',
	'drng/esdm_drng_mgr.c',
	'es/esdm_es_aux.c',
	'es/esdm_es_buf.c',
	'es/esdm_es_mgr.c',
	'esdm_config.c',
	'esdm_interface_dev_common.c',
	'esdm_lib.c',
	'esdm_selftest.c',
	'status/esdm_info.c',
	'status/esdm_shm_status.c',
	'status/esdm_status_txt.c',
])

dependencies_esdm_lib = [ json_c_dep ]
include_dirs_esdm_lib = [ include_dirs_server ]

if get_option('es_sched_ebpf').enabled() or get_option('es_irq_ebpf').enabled()
	subdir('es/ebpf')
	dependencies_esdm_lib += libbpf_dep
	include_dirs_esdm_lib += include_dirs_esdm_ebpf
	esdm_src += files('es/ebpf/esdm_es_ebpf.c')
	esdm_src += esdm_ebpf_skel_hdrs
	if get_option('es_sched_ebpf').enabled()
		esdm_src += files('es/ebpf/esdm_es_sched_ebpf.c')
	endif
	if get_option('es_irq_ebpf').enabled()
		esdm_src += files('es/ebpf/esdm_es_irq_ebpf.c')
	endif
endif

if get_option('es_jent').enabled()
	jitterentropy_dep = cc.find_library('jitterentropy')
	# find_library() does not verify the version, but ESDM relies on APIs
	# that older jitterentropy releases lack. Probe for the symbols actually
	# used so configuration fails with a clear message instead of a confusing
	# mid-compile or link error against a too-old library.
	foreach jent_sym : [ 'jent_entropy_init_ex',
			     'jent_read_entropy_safe',
			     'jent_entropy_collector_alloc' ]
		if not cc.has_function(jent_sym,
				       prefix: '#include <jitterentropy.h>',
				       dependencies: jitterentropy_dep)
			error('jitterentropy is too old (missing ' + jent_sym +
			      '); ESDM requires a newer jitterentropy library.')
		endif
	endforeach

	# The NTG.1 mode, the memory size, the hash loop count and the use of
	# all caches are flags of jitterentropy 3.7.0 and later. esdm_es_jent.c
	# leaves them out for an older one, which would ignore the options
	# without a word.
	if get_option('es_jent_ntg1').enabled() or \
	   get_option('es_jent_max_mem') != -1 or \
	   get_option('es_jent_hash_loop_count') != -1 or \
	   get_option('es_jent_all_caches').enabled()
		jent_version = cc.compute_int('JENT_VERSION',
					      prefix: '#include <jitterentropy.h>',
					      dependencies: jitterentropy_dep)
		if jent_version < 3070000
			error('es_jent_ntg1, es_jent_max_mem, es_jent_hash_loop_count and es_jent_all_caches need jitterentropy 3.7.0 or later, found @0@.@1@.@2@'.format(
			      jent_version / 1000000,
			      jent_version % 1000000 / 10000,
			      jent_version % 10000 / 100))
		endif
	endif

	dependencies_esdm_lib += jitterentropy_dep
	esdm_src += files('es/esdm_es_jent.c')
endif

if get_option('es_cpu').enabled()
	esdm_src += files('es/esdm_es_cpu.c')
endif

if get_option('es_irq').enabled()
	esdm_src += files('es/esdm_es_irq.c')
endif

if get_option('es_kernel').enabled()
	esdm_src += files('es/esdm_es_krng.c')
endif

if get_option('es_sched').enabled()
	esdm_src += files('es/esdm_es_sched.c')
endif

if get_option('es_hwrand').enabled()
	esdm_src += files('es/esdm_es_hwrand.c')
endif

if get_option('es_tpm2').enabled()
	esdm_src += files('es/esdm_es_tpm2.c')
endif

if get_option('es_ext').enabled()
	esdm_src += files('es/esdm_es_ext_status.c', 'es/esdm_es_extsock.c')
endif

if get_option('es_jent_kernel').enabled()
	dependencies_esdm_lib += cc.find_library('kcapi')
	esdm_src += files('es/esdm_es_jent_kernel.c')
endif

if get_option('node').enabled()
	esdm_src += files('drng/esdm_node.c')
endif

if get_option('fips140')
	esdm_src += files([ 'fips.c' ])
endif

if get_option('crypto_backend') == 'builtin'
	if get_option('drng_hash_drbg').enabled()
		esdm_src += files([ 'crypto/esdm_builtin_hash_drbg.c' ])
	endif

	if get_option('drng_chacha20').enabled()
		esdm_src += files([ 'crypto/esdm_builtin_chacha20.c' ])
	endif

	if get_option('hash_sha512').enabled() or \
	   get_option('hash_sha3_512').enabled()
		esdm_src += files([ 'crypto/esdm_builtin_sha512.c' ])
	endif

	esdm_src += files([ 'crypto/esdm_builtin_shake256.c' ])
elif get_option('crypto_backend') == 'botan'
	esdm_src += files([ 'crypto/esdm_botan.cpp' ])
	dependencies_esdm_lib += [ botan_dep ]
elif get_option('crypto_backend') == 'gnutls'
	esdm_src += files([ 'crypto/esdm_gnutls.c' ])
	dependencies_esdm_lib += [ gnutls_dep, nettle_dep ]
elif get_option('crypto_backend') == 'leancrypto'
	esdm_src += files([ 'crypto/esdm_leancrypto.c' ])
	dependencies_esdm_lib += [ leancrypto_dep ]
elif get_option('crypto_backend') == 'openssl'
	esdm_src += files([ 'crypto/esdm_openssl.c' ])
	dependencies_esdm_lib += [ openssl_dep ]
else
	error('Unknown crypto backend')
endif

esdm_common_static_lib = static_library('esdm_common_static',
	[ common_src, common_tls_src, crypto_src ],
	include_directories: include_dirs_server,
	dependencies: [ dependencies_client ],
	)

# For the ESDM server, which links libesdm next to it: without the logger and
# the thread pool, so that it uses the copies in libesdm and shares their state.
# Interposing its own copies does not work reliably - clang's LTO binds the
# library's internal calls to the library's copies.
esdm_server_common_static_lib = static_library('esdm_server_common_static',
	[ common_stateless_src, crypto_src ],
	include_directories: include_dirs_server,
	dependencies: [ dependencies_client ],
	build_by_default: false,
	)

esdm_static_lib = static_library('esdm_static',
	[ crypto_src, esdm_src ],
	 include_directories: include_dirs_esdm_lib,
	 dependencies: [ dependencies_esdm_lib ],
	 link_with: esdm_common_static_lib,
	)

# Symbol versioning for libesdm: Meson has no option for linker version scripts,
# so the flag goes through link_args; link_depends makes Ninja relink when
# version.lds changes. Version scripts are a GNU ld / LLD feature, hence the
# probe. Since binutils 2.41 and LLD 17 the linker defaults to
# --no-undefined-version, turning a symbol listed in the script but not built in
# this configuration into a hard error, so ask for the lenient behaviour where
# the option exists - older linkers are lenient anyway.
esdm_version_lds = meson.current_source_dir() / 'version.lds'
esdm_lib_link_args = [ '-Wl,--version-script,' + esdm_version_lds ]
if cc.has_link_argument('-Wl,--undefined-version')
	esdm_lib_link_args += [ '-Wl,--undefined-version' ]
endif

if not cc.has_multi_link_arguments(esdm_lib_link_args)
	warning('Linker does not support version scripts - libesdm.so exports every DSO_PUBLIC symbol')
	esdm_lib_link_args = []
endif

esdm_lib = library('esdm',
	[ common_src, crypto_src, esdm_src ],
	 include_directories: [ include_dirs_client, include_dirs_esdm_lib ],
	 dependencies: [ dependencies_client, dependencies_esdm_lib ],
	 version: meson.project_version(),
	 soversion: version_array[0],
	 link_args: esdm_lib_link_args,
	 link_depends: files('version.lds'),
	 install: true
	)

include_user_files += files([
	'esdm.h',
	'esdm_config.h'
])
