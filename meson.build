################################################################################
# Version Change Definition
################################################################################
# Major Version: API / ABI incompatible changes, functional changes that require
#		 consumer to be updated (as long as this number is zero, the API
#		 is not considered stable and can change without a bump of the
#		 major version).
# Minor Version: API compatible, ABI may change, functional enhancements only,
#		 consumer can be left unchanged if enhancements are not
#		 considered. Yet, consumer must be recompiled.
# Patchlevel Version: API / ABI compatible, no functional changes, no
#		      enhancements, bug fixes only.
project('esdm', 'c',
	version: '1.2.4',
	default_options: [
		'warning_level=3',
		'optimization=2',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pie=true',
		'b_asneeded=true',
		# set a fixed C std in order to not be compiler dependent here
		'c_std=gnu17',
		# set the C++ std for the botan frontend here, C++ only gets used
		# if the botan crypto backend is enabled
		'cpp_std=c++20',
	])

################################################################################
# Generic project defines
################################################################################

cc = meson.get_compiler('c')

# Hardening Compiler flags
add_global_arguments([ '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion',
		       '-Wcast-align',
		       '-Wmissing-field-initializers',
		       '-Wshadow',
		       '-Wmissing-prototypes',
		       '-Wswitch-enum',
		       '-Wformat=2',
                       ],
		       language : 'c')

# More hardening
if cc.has_argument('-fzero-call-used-regs=used-gpr')
	add_global_arguments([ '-fzero-call-used-regs=used-gpr' ],
			     language: 'c')
endif

# Control-flow and stack-clash protection (architecture dependent, so probe
# for support instead of assuming it).
foreach hardening_arg : [ '-fstack-clash-protection', '-fcf-protection=full' ]
	if cc.has_argument(hardening_arg)
		add_global_arguments([ hardening_arg ], language: 'c')
	endif
endforeach

if cc.has_argument('-ffat-lto-objects')
	add_global_arguments([ '-ffat-lto-objects' ],
			     language: 'c')
	if get_option('crypto_backend') == 'botan'
		add_global_arguments([ '-ffat-lto-objects' ],
				language: 'cpp')
	endif
endif

if get_option('optimization') != '0'
	# Undefine first to avoid a redefinition warning when the toolchain or
	# distro CFLAGS already inject a _FORTIFY_SOURCE level.
	add_global_arguments([ '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3' ],
			     language: 'c')
else
	add_global_arguments([ '-DDEBUG' ], language: 'c')
endif

# Apply the same hardening to the C++ (botan) backend, which otherwise builds
# with none of the flags above since those are added for language 'c' only.
# The C++ compiler is not configured for the host machine at this point (the
# project only declares 'c'), so do not call meson.get_compiler('cpp'); reuse
# the C compiler probes instead - the same toolchain compiles both languages,
# and add_global_arguments(language: 'cpp') is accepted here just like the
# -ffat-lto-objects case above.
if get_option('crypto_backend') == 'botan'
	cpp_hardening = [ '-fstack-protector-strong', '-fwrapv',
			  '--param', 'ssp-buffer-size=4', '-fvisibility=hidden' ]
	if get_option('optimization') != '0'
		cpp_hardening += [ '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3' ]
	endif
	foreach hardening_arg : [ '-fzero-call-used-regs=used-gpr',
				 '-fstack-clash-protection', '-fcf-protection=full' ]
		if cc.has_argument(hardening_arg)
			cpp_hardening += hardening_arg
		endif
	endforeach
	add_global_arguments(cpp_hardening, language: 'cpp')
endif

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
add_project_link_arguments('-Wl,--gc-sections', language : 'c')

# Link for full RELRO
add_project_link_arguments('-Wl,-z,relro', language : 'c')
add_project_link_arguments('-Wl,-z,now', language : 'c')

# No executable stack
add_project_link_arguments('-Wl,-z,noexecstack', language : 'c')

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

# use "required: true" in more recent meson version >= 1.3.0
if not cc.has_function('pthread_mutex_clocklock')
	assert(false, 'pthread_mutex_clocklock not found')
endif
if not cc.has_function('pthread_cond_clockwait')
	assert(false, 'pthread_cond_clockwait not found')
endif

################################################################################
# Project-specific defines
################################################################################

dependencies = [ dependency('libprotobuf-c'), dependency('threads') ]

# Rendering of the JSON status document and its parsing in the test suite
json_c_dep = dependency('json-c', required: true)

pkgconfig = import('pkgconfig')

include_user_files = [ ]

include_dirs_server = include_directories([ 'esdm',
					    'esdm/crypto',
					    'esdm/drng',
					    'kernel/shared',
					    'crypto',
					    'common',
					    'es-ext',
					    'service-egd',
					    'service-egd/server',
					    'service-rpc/service',
					    'service-rpc/server' ])
dependencies_server = dependencies + [ json_c_dep ]

include_dirs_client = include_directories([ 'common',
					    'service-egd',
					    'service-egd/client',
					    'service-rpc/service',
					    'service-rpc/client' ])
dependencies_client = dependencies

# The EGD client needs nothing but the common code - keep it that way by not
# handing it the RPC service includes.
include_dirs_egd_client = include_directories([ 'common',
						'service-egd',
						'service-egd/client' ])

include_dirs_es_ext = include_directories([ 'common', 'es-ext' ])

# The messages of the external ES protocol, see es-ext/pb/es_ext.proto: in the
# ESDM and in libesdm_es_ext
es_ext_proto_src = files('es-ext/es_ext.pb-c.c')
protobuf_c_dep = dependency('libprotobuf-c')

subdirs = [ 'common', 'crypto', 'esdm', 'service-egd',
	    'service-rpc/server', 'service-rpc/service' ]

# The interfaces of the esdm-server: each can be left out of the build, with its
# client library and everything that needs it.
server_rpc = get_option('esdm-server-rpc').enabled()
server_egd = get_option('esdm-server-egd').enabled()

if get_option('esdm-server').enabled() and not server_rpc and not server_egd
	error('The ESDM server needs an interface - enable esdm-server-rpc, esdm-server-egd or both')
endif

if server_rpc
	subdirs += [ 'service-rpc/client/' ]
else
	foreach opt : [ 'linux-devfiles', 'linux-getrandom' ]
		if get_option(opt).enabled()
			error(opt + ' uses the RPC interface of the ESDM server - disable it together with esdm-server-rpc')
		endif
	endforeach
	if get_option('openssl-rand-provider').enabled() and not server_egd
		error('The OpenSSL RAND provider needs an interface of the ESDM server - enable esdm-server-rpc or esdm-server-egd')
	endif
endif

if get_option('esdm-server').disabled() and get_option('linux-devfiles').enabled()
	error('Linux device file support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('linux-getrandom').enabled()
	error('Linux getrandom support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('openssl-rand-provider').enabled()
	error('OpenSSL RAND provider support requires the ESDM server')
endif

if not server_egd and get_option('esdm-cdev-check').enabled()
	error('esdm-cdev-check checks the kernel module esdm_cdev, which reads the ESDM through its EGD interface - enable esdm-server-egd')
endif

if get_option('es_jent_kernel').enabled()
	dependencies_server += [ dependency('libkcapi', required: true) ]
endif

if get_option('es_sched_ebpf').enabled() or get_option('es_irq_ebpf').enabled()
	dependencies_server += [ dependency('libbpf', version: '>= 1.2',
					    required: true) ]
endif

if get_option('es_ebpf_testing').enabled()
	if get_option('es_sched_ebpf').disabled() and \
	   get_option('es_irq_ebpf').disabled()
		error('es_ebpf_testing requires es_sched_ebpf or es_irq_ebpf to be enabled')
	endif
	subdirs += [ 'tests/es_ebpf_testing' ]
endif

if get_option('esdm-server').enabled()
	# The signal helper works over either interface, the kernel seeder
	# reads its seed over the RPC interface
	subdirs += [ 'frontends/server', 'frontends/server-signal-helper' ]
	if server_rpc
		subdirs += [ 'frontends/kernel-seeder' ]
	endif
endif

if get_option('linux-devfiles').enabled()
	subdirs += [ 'frontends/cuse' ]
endif

if get_option('linux-getrandom').enabled()
	subdirs += [ 'frontends/getrandom' ]
endif

################################################################################
# Crypto Backends/Frontends
################################################################################
if get_option('crypto_backend') == 'builtin'
	if get_option('drng_hash_drbg').enabled() and \
	   get_option('drng_chacha20').enabled()
		error('Only one DRNG can be enabled')
	endif

	if get_option('hash_sha512').enabled() and \
	   get_option('hash_sha3_512').enabled()
		error('Only one conditioning hash can be enabled')
	endif
endif

if get_option('crypto_backend') == 'gnutls'
	# 3.6.7: esdm_gnutls.c declares GnuTLS' private struct drbg_aes_ctx,
	# which 3.5 to 3.6.3 at least lay out larger: GnuTLS would overrun it.
	gnutls_dep = dependency('gnutls', version: '>= 3.6.7', required: true)

	# The SP800-90A Block_Cipher_df in front of GnuTLS' CTR DRBG uses the
	# AES-256 core directly. GnuTLS only lists nettle in Requires.private,
	# so it has to be linked explicitly.
	# The SHAKE256 of the auxiliary pool is nettle's as well, which has it
	# since 3.6.
	nettle_dep = dependency('nettle', version: '>= 3.6', required: true)

	# The CTR DRBG this backend drives (drbg_aes_init/reseed/generate) is
	# not part of the regular GnuTLS ABI: those three live in the
	# GNUTLS_FIPS140_3_4 version node and are only exported by a GnuTLS
	# configured with --enable-fips140-mode. Distribution builds generally
	# are not, and then the only symptom is a pile of undefined references
	# at link time - so check for it here and say what is actually wrong.
	if not cc.has_function('drbg_aes_init', dependencies: gnutls_dep)
		error('''The GnuTLS backend needs the SP800-90A CTR DRBG symbols
(drbg_aes_init/reseed/generate), which GnuTLS only exports when it is built
with --enable-fips140-mode. The GnuTLS found here does not export them.
Rebuild GnuTLS with FIPS140 mode enabled, or select another crypto_backend.''')
	endif
endif

if get_option('crypto_backend') == 'leancrypto'
	# 1.6.0: lc_hash_init() reports a failed self test instead of asserting
	# A system include: its headers are not built to -Wpedantic
	leancrypto_dep = dependency('leancrypto', version: '>= 1.6.0', required: true,
				    include_type: 'system')
endif

if get_option('crypto_backend') == 'botan'
	add_languages('cpp', required: true)
	# Botan::XOF, the SHAKE256 of the auxiliary pool, came with 3.2
	botan_dep = dependency('botan-3', version: '>= 3.2', required: true)
endif

if get_option('crypto_backend') == 'openssl' or get_option('openssl-rand-provider').enabled()
	openssl_dep = dependency('openssl', version : '>=3.0', required: true)
endif

if get_option('openssl-rand-provider').enabled()
	subdirs += [ 'frontends/openssl-provider' ]
endif

################################################################################
# ESDM and client libraries
################################################################################
if get_option('esdm-aux-client').enabled()
	include_dirs_aux_client = [
		include_directories('frontends/aux-client')
	]
	subdirs += [ 'frontends/aux-client' ]
else
	include_dirs_aux_client = []
endif

if get_option('esdm-es-ext').enabled()
	subdirs += [ 'es-ext' ]
endif

foreach opt : [ 'es_pkcs11', 'es_pcsc' ]
	if get_option(opt).enabled() and not get_option('esdm-es-ext').enabled()
		error(opt + ' builds a provider of libesdm_es_ext - enable esdm-es-ext')
	endif
endforeach

# esdm-tool works over the RPC interface or, without it, over the EGD interface
if get_option('esdm-tool').enabled()
	if not server_rpc and not server_egd
		error('esdm-tool needs an interface of the ESDM server - enable esdm-server-rpc or esdm-server-egd')
	endif
	subdirs += [ 'frontends/tool' ]
endif

if get_option('validation-helpers').enabled()
	subdirs += [ 'tests/validation-helpers' ]
endif

subdirs += [ 'man' ]

foreach n : subdirs
	subdir(n)
endforeach

install_headers(include_user_files, subdir: 'esdm')

################################################################################
# Execute testing
################################################################################

testdirs = [
	'tests/common',
	'tests/crypto',
	'tests/cuse',
	'tests/es',
	'tests/es_ext',
	'tests/esdm',
	'tests/getrandom',
	'tests/misc',
	'tests/proc',
	'tests/security',
	'tests/server',
	'tests/server-signal-helper',
	'tests/aux-client',
	'tests/tool',
	]
# The RPC interface and what reaches the server through it
if server_rpc
testdirs += [
	'tests/kernel-seeder',
	'tests/rpc_client',
	'tests/rpc_service',
]
endif
# The EGD interface, and esdm_cdev as its client in the kernel
if server_egd
testdirs += [
	'tests/egd',
	'tests/esdm_cdev',
]
endif
if get_option('fuzzing').enabled()
testdirs += [
	'tests/fuzz',
]
endif
if get_option('openssl-rand-provider').enabled()
testdirs += [
	'tests/openssl-rand-provider',
]
endif
foreach n : testdirs
	subdir(n)
endforeach

