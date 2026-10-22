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

# Code generation hardening (architecture and compiler dependent, so probe for
# support instead of assuming it): zero all call-clobbered registers a function
# used on return, so no key material or random bytes linger in them, plus
# control-flow and stack-clash protection. They are passed to the link as well:
# with LTO, the code is generated there, and GCC drops at least
# -fzero-call-used-regs that only the compile step saw.
codegen_hardening = []
foreach hardening_arg : [ '-fzero-call-used-regs=used',
			  '-fstack-clash-protection', '-fcf-protection=full' ]
	if cc.has_argument(hardening_arg)
		codegen_hardening += hardening_arg
	endif
endforeach
add_global_arguments(codegen_hardening, language: 'c')
add_global_link_arguments(codegen_hardening, language: 'c')

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
	cpp_hardening += codegen_hardening
	add_global_arguments(cpp_hardening, language: 'cpp')
	# libesdm links botan and therefore with the C++ driver.
	add_global_link_arguments(codegen_hardening, language: 'cpp')
endif

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# The link arguments below are given for C++ as well: a target with a C++
# source - libesdm with the botan backend, and everything linking it - is
# linked by the C++ driver with the C++ link arguments alone, and lost them
# otherwise. Like the C++ arguments above, they are accepted before the botan
# backend adds the language, and unused without it.

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'],
		     language : ['c', 'cpp'])
add_project_link_arguments('-Wl,--gc-sections', language : ['c', 'cpp'])

# Link for full RELRO
add_project_link_arguments('-Wl,-z,relro', language : ['c', 'cpp'])
add_project_link_arguments('-Wl,-z,now', language : ['c', 'cpp'])

# No executable stack
add_project_link_arguments('-Wl,-z,noexecstack', language : ['c', 'cpp'])

# The client libraries export the logger so that the copy of the frontend
# linking them interposes theirs. Clang drops that interposition under LTO and
# binds the library's own calls to its own copy unless told otherwise (GCC's
# default already keeps it).
add_project_arguments(cc.get_supported_arguments('-fsemantic-interposition'),
		      language : 'c')

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

# Rendering of the JSON status document and its parsing in the test suite.
# The parsing of the status of an external entropy source needs
# json_tokener_get_parse_end(), which came with 0.14 - as did the
# JSON_TOKENER_VALIDATE_UTF8 flag of the tokener.
json_c_dep = dependency('json-c', version: '>= 0.14', required: true)

pkgconfig = import('pkgconfig')

include_user_files = [ ]

# The code shared by the ESDM, its libraries and frontends is sorted into the
# subfolders of common/ by type; its headers are included by their names.
include_dirs_server = include_directories([ 'esdm',
					    'esdm/crypto',
					    'esdm/drng',
					    'esdm/es',
					    'esdm/es/cpu',
					    'esdm/es/ebpf',
					    'esdm/status',
					    'kernel/shared',
					    'crypto',
					    'common',
					    'common/log',
					    'common/sys',
					    'common/testmode',
					    'common/threading',
					    'common/tls',
					    'common/util',
					    'es-ext',
					    'service-egd',
					    'service-egd/server',
					    'service-rpc/service',
					    'service-rpc/server' ])
dependencies_server = dependencies + [ json_c_dep ]

include_dirs_client = include_directories([ 'common',
					    'common/log',
					    'common/sys',
					    'common/testmode',
					    'common/threading',
					    'common/tls',
					    'common/util',
					    'service-egd',
					    'service-egd/client',
					    'service-rpc/service',
					    'service-rpc/client' ])
dependencies_client = dependencies

# The external entropy source library needs the common code and the socket
# creation of the servers - see es-ext/meson.build.
include_dirs_es_ext = include_directories([ 'common',
					    'common/log',
					    'common/sys',
					    'common/testmode',
					    'common/threading',
					    'common/tls',
					    'common/util',
					    'es-ext',
					    'service-egd/server' ])

# For the tests looking up symbols with dlsym(3) - in the C library itself
# since glibc 2.34

dl_dep = dependency('dl')

# The EGD client needs nothing but the common code - keep it that way by not
# handing it the RPC service includes.
include_dirs_egd_client = include_directories([ 'common',
						'common/log',
						'common/sys',
						'common/testmode',
						'common/threading',
						'common/tls',
						'common/util',
						'service-egd',
						'service-egd/client' ])

subdirs = [ 'common', 'crypto', 'esdm', 'service-egd',
	    'service-rpc/server', 'service-rpc/service', 'service-rpc/client/' ]

if get_option('esdm-server').disabled() and get_option('linux-devfiles').enabled()
	error('Linux device file support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('linux-getrandom').enabled()
	error('Linux getrandom support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('openssl-rand-provider').enabled()
	error('OpenSSL RAND provider support requires the ESDM server')
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
	subdirs += [ 'frontends/server', 'frontends/server-signal-helper', 'frontends/kernel-seeder' ]
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

	# The builtin backend has nothing else to fall back on
	if not get_option('drng_hash_drbg').enabled() and \
	   not get_option('drng_chacha20').enabled()
		error('The builtin crypto backend needs a DRNG - enable drng_hash_drbg or drng_chacha20')
	endif

	if not get_option('hash_sha512').enabled() and \
	   not get_option('hash_sha3_512').enabled()
		error('The builtin crypto backend needs a conditioning hash - enable hash_sha512 or hash_sha3_512')
	endif
endif

if get_option('crypto_backend') == 'gnutls'
	# esdm_gnutls.c copies GnuTLS' private struct drbg_aes_ctx, which had
	# a larger layout (prev_block) up to at least 3.6.4. 3.6.8 is the first
	# release verified to match.
	gnutls_dep = dependency('gnutls', version: '>= 3.6.8', required: true)

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
	leancrypto_dep = dependency('leancrypto', version: '>= 1.0', required: true)
endif

if get_option('crypto_backend') == 'botan'
	add_languages('cpp', required: true)
	# Botan::XOF, the SHAKE256 of the auxiliary pool, came with 3.2
	botan_dep = dependency('botan-3', version: '>= 3.2', required: true)
endif

if get_option('crypto_backend') == 'openssl' or get_option('openssl-rand-provider').enabled()
	openssl_dep = dependency('openssl', version : '>=3.0', required: true)
endif

# The DTLS of the connections is provided by the TLS stack of the crypto
# backend - see common/tls/esdm_dtls.h. Everything speaking to another process
# is built with dependencies_client or dependencies_server, so the stack is
# handed to all of them; one not using it is not linked against it
# (b_asneeded).
if get_option('dtls').enabled()
	if get_option('crypto_backend') == 'openssl'
		dtls_deps = [ openssl_dep ]
	elif get_option('crypto_backend') == 'gnutls'
		dtls_deps = [ gnutls_dep ]
	elif get_option('crypto_backend') == 'botan'
		dtls_deps = [ botan_dep ]
	else
		error('dtls needs the TLS stack of crypto_backend openssl, gnutls or botan - the ' + get_option('crypto_backend') + ' backend has none')
	endif
	dependencies_client += dtls_deps
	dependencies_server += dtls_deps
else
	dtls_deps = []
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

# The PKCS#11 entropy source is a provider served by the library of the
# external entropy sources - see es-ext/meson.build
if get_option('es_pkcs11').enabled() and get_option('esdm-es-ext').disabled()
	error('es_pkcs11 builds esdm-es-pkcs11, a provider served by libesdm_es_ext - enable esdm-es-ext as well')
endif

if get_option('esdm-tool').enabled()
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
	'tests/abi',
	'tests/common',
	'tests/crypto',
	'tests/cuse',
	'tests/egd',
	'tests/es',
	'tests/es_ext',
	'tests/esdm',
	'tests/esdm_cdev',
	'tests/getrandom',
	'tests/kernel-seeder',
	'tests/misc',
	'tests/proc',
	'tests/rpc_client',
	'tests/rpc_service',
	'tests/server',
	'tests/server-signal-helper',
	'tests/aux-client',
	'tests/tool',
	# The fuzz harnesses with -Dfuzzing=enabled, and the regression tests
	# built with their entry points always
	'tests/fuzz',
	]
if get_option('openssl-rand-provider').enabled()
testdirs += [
	'tests/openssl-rand-provider',
]
endif
foreach n : testdirs
	subdir(n)
endforeach

