# The logger and the thread pool keep process-wide state. The ESDM server must
# share it with libesdm, so it takes them from the library instead of linking
# copies of its own - see esdm_server_common_static_lib.
common_state_src = files([
	'log/esdm_logger.c',
	'threading/threading_support.c',
])

common_src = files([
	'sys/linux_support.c',
	'sys/os_random.c',
	'util/binhexbin.c',
	'util/buffer.c',
	'util/helper.c',
	'util/xoshiro_prng.c',
])

if get_option('systemd').enabled()
	common_src += files(['sys/systemd_support.c'])
endif

if get_option('testmode').enabled()
	common_src += files(['testmode/test_pertubation.c'])
endif

if get_option('fips140')
	common_src += files(['sys/fips_integrity.c'])
endif

# The backend of the TLS stack of the crypto backend, see esdm_tls_backend.h:
# the (D)TLS of both the local DTLS of the connections and the TLS with
# certificates. The builtin and the leancrypto backend have no TLS stack, and
# neither the one nor the other.
tls_backend_src = []
if get_option('crypto_backend') in [ 'openssl', 'gnutls', 'botan' ]
	tls_backend_src = files([
		'tls/esdm_tls_' + get_option('crypto_backend') +
			(get_option('crypto_backend') == 'botan' ? '.cpp' : '.c'),
	])
endif

# The DTLS of the connections - see esdm_dtls.h and the dtls option in the
# top-level meson.build: the core of the backend, which is all a library with
# the local DTLS alone links - the functions of the certificates, compiled
# with the TLS with certificates only, are dropped by the linker where nothing
# calls them. The messages on top of the records are there for the TLS with
# certificates of es-ext-net as well.
if get_option('dtls').enabled() or es_ext_net
	common_src += files([ 'tls/esdm_dtls.c' ])
endif
if get_option('dtls').enabled()
	common_src += tls_backend_src
endif

# The TLS with certificates of the EGD protocol and of the external entropy
# sources over the network - see esdm_tls.h and the egd-net and es-ext-net
# options in the top-level meson.build. Built into the static common library
# only: libesdm has no use for it, and would only depend on the TLS stack for
# it. The backend comes along with it, unless the DTLS of the connections has
# it in common_src already.
common_tls_src = []
if tls_auth
	common_tls_src += files([ 'tls/esdm_tls.c' ])
	if not get_option('dtls').enabled()
		common_tls_src += tls_backend_src
	endif
endif
if es_ext_net
	common_tls_src += files([ 'tls/esdm_dtls_tls.c' ])
endif

# What the daemons serving the network share - see esdm_net.h. Into the static
# common library only, as the TLS layer.
if egd_net or es_ext_net
	common_tls_src += files([ 'tls/esdm_net.c' ])
endif

common_stateless_src = common_src
common_src += common_state_src

conf_data = configuration_data()

conf_data.set('ESDM_SYSTEMD_SUPPORT', get_option('systemd').enabled())

if get_option('ais2031_drg3') and get_option('ais2031_drg4')
	error('ais2031_drg3 and ais2031_drg4 are mutually exclusive - the one option skips the reseeding limits that the other configures.')
endif

# FIPS 140 implies the SP800-90C compliance mode - the runtime forces it on
# whenever the oversampling is compiled in - so a fips140 build is configured
# exactly as if sp80090c were set alongside it.
sp80090c_mode = get_option('sp80090c') or get_option('fips140')

# DRG.3 is the way to ask for the entropy source oversampling without the
# request size based reseeding limits that the sp80090c option brings with it.
# Everything keyed on the oversampling below therefore reads this variable
# rather than sp80090c_mode; the thresholds further down are left to
# sp80090c_mode, so that a DRG.3 build does not pick them up.
sp80090c = sp80090c_mode or get_option('ais2031_drg3')

conf_data.set('ESDM_OVERSAMPLE_ENTROPY_SOURCES', sp80090c)
conf_data.set('ESDM_AIS2031_NTG1_SEEDING_STRATEGY', get_option('ais2031_ntg1'))
conf_data.set('ESDM_AIS2031_DRG3', get_option('ais2031_drg3'))
conf_data.set('ESDM_AIS2031_DRG4', get_option('ais2031_drg4'))
if sp80090c
	# The values the kernel module esdm_es applies in a FIPS kernel, from
	# the header the two share: the seed size makes up the entropy buffer
	# its IOCTLs hand over.
	foreach osr : [ 'SEED_BUFFER_INIT_ADD_BITS', 'OVERSAMPLE_ES_BITS' ]
		conf_data.set('ESDM_' + osr,
			      cc.get_define('ESDM_SP80090C_' + osr,
					    prefix: '#include "esdm_seed_sizes.h"',
					    include_directories: include_directories('../kernel/shared')).to_int())
	endforeach
else
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 0)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 0)
endif

if get_option('crypto_backend') == 'builtin'
	conf_data.set('ESDM_DRNG_HASH_DRBG', get_option('drng_hash_drbg').enabled())
	conf_data.set('ESDM_DRNG_CHACHA20', get_option('drng_chacha20').enabled())
	conf_data.set('ESDM_HASH_SHA512', get_option('hash_sha512').enabled())
	conf_data.set('ESDM_HASH_SHA3_512', get_option('hash_sha3_512').enabled())
else
	conf_data.set('ESDM_DRNG_HASH_DRBG', false)
	conf_data.set('ESDM_DRNG_CHACHA20', false)
	conf_data.set('ESDM_HASH_SHA512', false)
	conf_data.set('ESDM_HASH_SHA3_512', false)
endif

if get_option('crypto_backend') == 'gnutls'
	conf_data.set('ESDM_GNUTLS', true)
else
	conf_data.set('ESDM_GNUTLS', false)
endif

if get_option('crypto_backend') == 'leancrypto'
	conf_data.set('ESDM_LEANCRYPTO', true)
	# Since leancrypto 1.6.0, lc_hash_init() reports a failed self test
	conf_data.set('ESDM_LEANCRYPTO_HASH_INIT_RET',
		      leancrypto_dep.version().version_compare('>= 1.6.0'))
else
	conf_data.set('ESDM_LEANCRYPTO', false)
	conf_data.set('ESDM_LEANCRYPTO_HASH_INIT_RET', false)
endif

if get_option('crypto_backend') == 'openssl'
	conf_data.set('ESDM_OPENSSL', true)
else
	conf_data.set('ESDM_OPENSSL', false)
endif

if get_option('crypto_backend') == 'botan'
	conf_data.set('ESDM_BOTAN', true)
else
	conf_data.set('ESDM_BOTAN', false)
endif

conf_data.set('ESDM_OPENSSL_DRNG_CTR', get_option('openssl_drng_type') == 'ctr')
conf_data.set('ESDM_OPENSSL_DRNG_HASH', get_option('openssl_drng_type') == 'hash')
conf_data.set('ESDM_OPENSSL_DRNG_HMAC', get_option('openssl_drng_type') == 'hmac')

conf_data.set('ESDM_BOTAN_DRNG_CHACHA20', get_option('botan_drng_type') == 'chacha20')
conf_data.set('ESDM_BOTAN_DRNG_HMAC', get_option('botan_drng_type') == 'hmac')

conf_data.set('THREADING_MAX_WORKER_THREADS', get_option('threading_max_worker_threads'))
conf_data.set('THREADING_MAX_THREADS', get_option('threading_max_worker_threads') + 3)

conf_data.set('ESDM_ES_PARALLEL_FETCH', get_option('es_parallel_fetch').enabled())

conf_data.set('ESDM_ES_JENT', get_option('es_jent').enabled())
conf_data.set('ESDM_JENT_ENTROPY_RATE',
	      get_option('es_jent_entropy_rate'))
conf_data.set('ESDM_JENT_OSR',
	      get_option('es_jent_osr'))
conf_data.set('ESDM_JENT_NTG1',
	      get_option('es_jent_ntg1').enabled())
conf_data.set('ESDM_JENT_MAX_MEM',
	      get_option('es_jent_max_mem'))
conf_data.set('ESDM_JENT_HASH_LOOP_COUNT',
	      get_option('es_jent_hash_loop_count'))
conf_data.set('ESDM_JENT_ALL_CACHES',
	      get_option('es_jent_all_caches').enabled())

# Async per-ES buffering (es_buf) is incompatible with SP800-90C oversampled
# seeding by default. When the oversampling is compiled in (sp80090c, fips140 or
# ais2031_drg3), zero out every ESDM_*_ENTROPY_BLOCKS count so esdm_es_buf
# compiles out of all ES sources. The es_buf_force option
# overrides this and keeps the per-ES counts honored.
disable_es_buf = sp80090c and not get_option('es_buf_force')

# esdm_es_buf_alloc() refuses any other block count at runtime, which silently
# leaves the ES without its cache. A power of two up to 2^31 is what divides
# 2^31, meson having no bitwise operators.
foreach es_blocks_opt : ['es_jent_entropy_blocks', 'es_irq_entropy_blocks',
			 'es_sched_entropy_blocks', 'es_hwrand_entropy_blocks',
			 'es_tpm2_entropy_blocks', 'es_jent_kernel_entropy_blocks']
	es_blocks = get_option(es_blocks_opt)
	if es_blocks != 0 and (es_blocks < 4 or 2147483648 % es_blocks != 0)
		error(es_blocks_opt + ' must be 0 or a power of two of at least 4')
	endif
endforeach

# In esdm_es_jent.c the ESDM_JENT_ENTROPY_BLOCKS are divided by 4 and yet
# need to result in a value larger than zero
if get_option('es_jent_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS',
		      get_option('es_jent_entropy_blocks'))
else
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_CPU', get_option('es_cpu').enabled())
conf_data.set('ESDM_CPU_ENTROPY_RATE',
	      get_option('es_cpu_entropy_rate'))
conf_data.set('ESDM_CPU_FULL_ENT_MULTIPLIER',
	      get_option('es_cpu_multiplier'))

conf_data.set('ESDM_ES_IRQ', get_option('es_irq').enabled())
conf_data.set('ESDM_IRQ_ENTROPY_RATE',
	      get_option('es_irq_entropy_rate'))
if get_option('es_irq_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_IRQ_ENTROPY_BLOCKS',
		      get_option('es_irq_entropy_blocks'))
else
	conf_data.set('ESDM_IRQ_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_KERNEL_RNG', get_option('es_kernel').enabled())
conf_data.set('ESDM_KERNEL_RNG_ENTROPY_RATE',
	      get_option('es_kernel_entropy_rate'))

conf_data.set('ESDM_ES_SCHED', get_option('es_sched').enabled())
conf_data.set('ESDM_SCHED_ENTROPY_RATE',
	      get_option('es_sched_entropy_rate'))
if get_option('es_sched_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_SCHED_ENTROPY_BLOCKS',
		      get_option('es_sched_entropy_blocks'))
else
	conf_data.set('ESDM_SCHED_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_SCHED_EBPF', get_option('es_sched_ebpf').enabled())
conf_data.set('ESDM_SCHED_EBPF_ENTROPY_RATE',
	      get_option('es_sched_ebpf_entropy_rate'))
conf_data.set('ESDM_SCHED_EBPF_OSR',
	      get_option('es_sched_ebpf_osr'))

conf_data.set('ESDM_ES_IRQ_EBPF', get_option('es_irq_ebpf').enabled())
conf_data.set('ESDM_IRQ_EBPF_ENTROPY_RATE',
	      get_option('es_irq_ebpf_entropy_rate'))
conf_data.set('ESDM_IRQ_EBPF_OSR',
	      get_option('es_irq_ebpf_osr'))

conf_data.set('ESDM_ES_EBPF_TESTING', get_option('es_ebpf_testing').enabled())

conf_data.set('ESDM_ES_HWRAND', get_option('es_hwrand').enabled())
conf_data.set('ESDM_HWRAND_ENTROPY_RATE',
	      get_option('es_hwrand_entropy_rate'))
if get_option('es_hwrand_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_HWRAND_ENTROPY_BLOCKS',
		      get_option('es_hwrand_entropy_blocks'))
else
	conf_data.set('ESDM_HWRAND_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_TPM2', get_option('es_tpm2').enabled())
conf_data.set('ESDM_TPM2_ENTROPY_RATE',
	      get_option('es_tpm2_entropy_rate'))
conf_data.set('ESDM_TPM2_STIR', get_option('es_tpm2_stir').enabled())
conf_data.set_quoted('ESDM_TPM2_RM_PATH', get_option('es_tpm2_rm_path'))
if get_option('es_tpm2_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_TPM2_ENTROPY_BLOCKS',
		      get_option('es_tpm2_entropy_blocks'))
else
	conf_data.set('ESDM_TPM2_ENTROPY_BLOCKS', 0)
endif

# The defaults of esdm-es-pkcs11, the PKCS#11 entropy source served to the
# ESDM as an external one - see es-ext/meson.build
conf_data.set('ESDM_PKCS11_ENTROPY_RATE',
	      get_option('es_pkcs11_entropy_rate'))
conf_data.set_quoted('ESDM_PKCS11_MODULE_PATH',
		     get_option('es_pkcs11_module_path'))
conf_data.set_quoted('ESDM_PKCS11_TOKEN_LABEL',
		     get_option('es_pkcs11_token_label'))

conf_data.set('ESDM_ES_EXT', get_option('es_ext').enabled())

# The external entropy sources: their number, and the X-macro
# ESDM_EXT_SOCKET_INSTANCES(X) expanding X(i) for each of their indices i, from
# which the code generates what each instance needs - see esdm_es_extsock.c
es_ext_socket_num = 0
if get_option('es_ext').enabled()
	es_ext_socket_num = get_option('es_ext_socket_num')
endif
es_ext_instances = []
foreach i : range(es_ext_socket_num)
	es_ext_instances += 'X(@0@)'.format(i)
endforeach
conf_data.set('ESDM_EXT_SOCKET_NUM', es_ext_socket_num)
conf_data.set('ESDM_EXT_SOCKET_INSTANCES(X)', ' '.join(es_ext_instances))


# The configuration of the external sources: the i-th entry of a list sets
# ESDM_EXT_SOCKET_*_<i> for the i-th source. A path for each source, or for
# fewer, the others getting none; a rate or a uid for each source, or one for
# all of them.
foreach es_ext_opt : [
		[ 'es_ext_socket_path', 'ESDM_EXT_SOCKET_PATH_' ],
		[ 'es_ext_socket_entropy_rate',
		  'ESDM_EXT_SOCKET_ENTROPY_RATE_' ],
		[ 'es_ext_socket_peer_uid', 'ESDM_EXT_SOCKET_PEER_UID_' ] ]
	es_ext_name = es_ext_opt[0]
	es_ext_num = es_ext_socket_num
	es_ext_is_path = es_ext_name.endswith('_path')
	es_ext_is_uid = es_ext_name.endswith('_uid')

	# Every value is checked, whether a source of the build takes it or
	# not: a rate is a number from 0 to 256 or auto, a uid one from 0 to
	# 4294967294 or -1. What is left is the value without white space
	# around it.
	es_ext_vals = []
	foreach es_ext_raw : get_option(es_ext_name)
		es_ext_val = es_ext_raw.strip()
		es_ext_vals += es_ext_val
		if es_ext_is_path or \
		   (es_ext_is_uid and es_ext_val == '-1') or \
		   (not es_ext_is_uid and es_ext_val == 'auto')
			continue
		endif

		es_ext_int = -2
		if es_ext_val != '' and es_ext_val.strip('0123456789') == ''
			# Nothing but digits
			es_ext_int = es_ext_val.to_int()
		endif
		if es_ext_is_uid and (es_ext_int < 0 or es_ext_int > 4294967294)
			error('@0@ takes uids from 0 to 4294967294, or -1, not "@1@"'.format(
			      es_ext_name, es_ext_val))
		elif not es_ext_is_uid and (es_ext_int < 0 or es_ext_int > 256)
			error('@0@ takes entropy rates from 0 to 256 or auto, not "@1@"'.format(
			      es_ext_name, es_ext_val))
		endif
	endforeach

	if es_ext_num == 0
		# No source is built: say so, unless it is the default
		es_ext_default = es_ext_is_uid ? [ '-1' ] : []
		if get_option(es_ext_name) != es_ext_default
			warning('@0@ is ignored, as es_ext is disabled'.format(
				es_ext_name))
		endif
		continue
	endif

	if es_ext_is_path
		if es_ext_vals.length() > es_ext_num
			error('@0@ names @1@ paths, for @2@ sources'.format(
			      es_ext_name, es_ext_vals.length(), es_ext_num))
		endif
	elif es_ext_vals.length() <= 1
		# None configured for any source, or one for all
		es_ext_one = es_ext_is_uid ? '-1' : 'auto'
		if es_ext_vals.length() == 1
			es_ext_one = es_ext_vals[0]
		endif

		es_ext_vals = []
		foreach i : range(es_ext_num)
			es_ext_vals += es_ext_one
		endforeach
	elif es_ext_vals.length() != es_ext_num
		error('@0@ takes one value for all sources or one for each of the @1@ sources, not @2@ values'.format(
		      es_ext_name, es_ext_num, es_ext_vals.length()))
	endif

	foreach i : range(es_ext_num)
		es_ext_define = es_ext_opt[1] + i.to_string()
		es_ext_val = i < es_ext_vals.length() ? es_ext_vals[i] : ''
		if es_ext_is_path
			conf_data.set_quoted(es_ext_define, es_ext_val)
		elif es_ext_val == 'auto'
			# No rate configured: the one the source declares
			conf_data.set(es_ext_define, 'ESDM_ES_EXT_ENTROPY_RATE_AUTO')
		elif es_ext_val == '-1'
			conf_data.set(es_ext_define, -1)
		else
			conf_data.set(es_ext_define, es_ext_val.to_int())
		endif
	endforeach
endforeach
conf_data.set('ESDM_DTLS', get_option('dtls').enabled())
conf_data.set('ESDM_EGD_NET', egd_net)
conf_data.set('ESDM_EGD_NET_TLS', egd_net_tls)
# The TLS layer with certificates, esdm_tls.h
conf_data.set('ESDM_TLS_AUTH', tls_auth)
conf_data.set('ESDM_ES_EXT_NET', es_ext_net)
conf_data.set('ESDM_ES_EXT_NET_PORT', get_option('es-ext-net-port'))
conf_data.set('ESDM_EGD_NET_PORT', get_option('egd-net-port'))
# The TLS module of libesdm_egd_client, see esdm_egd_client_tls.h
conf_data.set_quoted('ESDM_EGD_TLS_MODULE_PATH',
		     get_option('prefix') / get_option('libdir') / 'esdm' /
		     'esdm-egd-tls.so')

conf_data.set('ESDM_ES_JENT_KERNEL', get_option('es_jent_kernel').enabled())
if get_option('es_jent_kernel_name') == '' or get_option('es_jent_kernel_name').contains('"')
	error('es_jent_kernel_name must name a kernel crypto API RNG')
endif
conf_data.set_quoted('ESDM_JENT_KERNEL_NAME', get_option('es_jent_kernel_name'))
conf_data.set('ESDM_JENT_KERNEL_ENTROPY_RATE',
	      get_option('es_jent_kernel_entropy_rate'))
if get_option('es_jent_kernel_entropy_blocks') >= 4 and not disable_es_buf
	conf_data.set('ESDM_JENT_KERNEL_ENTROPY_BLOCKS',
		      get_option('es_jent_kernel_entropy_blocks'))
else
	conf_data.set('ESDM_JENT_KERNEL_ENTROPY_BLOCKS', 0)
endif

# Only the sources built in count: the rate of a disabled one is not used
timing_es_credited = 0
foreach timing_es : [ 'es_irq', 'es_sched', 'es_irq_ebpf', 'es_sched_ebpf' ]
	if get_option(timing_es).enabled() and \
	   get_option(timing_es + '_entropy_rate') > 0
		timing_es_credited += 1
	endif
endforeach
if timing_es_credited > 1
	error('It is not permissible to award more than one of the enabled interrupt and scheduler-based entropy sources (es_irq, es_sched, es_irq_ebpf, es_sched_ebpf) an entropy rate greater than zero. Adjust the respective entropy rate options to zero, or disable the source.')
endif

conf_data.set('ESDM_SELINUX_ENABLED', get_option('selinux').enabled())
conf_data.set('ESDM_NODE', get_option('node').enabled())
conf_data.set('ESDM_FIPS140', get_option('fips140'))

conf_data.set('ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT', get_option('client-connect-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT', get_option('client-rx-tx-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RECONNECT_ATTEMPTS', get_option('client-reconnect-attempts'))
conf_data.set('ESDM_MAX_RX_TX_RETRIES', 5)

# chunk pr requests, such that slow entropy sources return fast in server
# and don't block the server longer than client read timeouts on average
conf_data.set('ESDM_RPC_MAX_PR_REQUEST_SIZE', 32)

conf_data.set('ESDM_TESTMODE', get_option('testmode').enabled())

conf_data.set('ESDM_GETRANDOM_NUM_NODES', get_option('linux-getrandom-num-nodes'))

conf_data.set('ESDM_LINUX_RESEED_INTERVAL_SEC', get_option('linux-reseed-interval'))
conf_data.set('ESDM_LINUX_RESEED_ENTROPY_COUNT', get_option('linux-reseed-entropy-count'))

# sp80090c_mode rather than the sp80090c variable above, and DRG.3 excluded
# outright: these caps are the DRG.4 reseeding limits, and skipping them is the
# whole point of the DRG.3 option. A build asking for it keeps whatever
# thresholds it configured, even where sp80090c or fips140 is set alongside.
if not get_option('ais2031_drg3') and (sp80090c_mode or get_option('ais2031_drg4'))
	reseed_thresh = get_option('drng_reseed_threshold_bits')
	max_reseed = get_option('drng_max_reseed_bits')

	# SP800-90C and AIS 20/31 DRG.4.10 cap the bits a DRNG may produce
	# without a full reseed at 2**17.
	if max_reseed > 131072
		max_reseed = 131072
	endif

	# Where inside that limit the reseed is triggered decides two things
	# that pull against each other: how often the entropy sources are
	# walked, and how much output a DRNG has left to cover the walk with.
	# The reseed of a node DRNG is handed to a worker, and everything the
	# DRNG may still produce before the limit above is the budget that
	# worker has to finish in.
	#
	# Three quarters, measured rather than picked: reseeding is expensive
	# enough that the frequency dominates. Moving the trigger from a half to
	# three quarters gains 13-16% throughput, and the remaining quarter -
	# 32768 bits of output - is what the asynchronous reseed gets to land
	# in. Going further flattens out (87% and 100% add a few percent more)
	# and at the limit itself the headroom is gone: every node DRNG then
	# reaches the maximum at the moment it asks to be reseeded and drops out
	# of the fully seeded state until the worker catches up, which only a
	# machine with several nodes can absorb.
	if reseed_thresh > (max_reseed / 4) * 3
		reseed_thresh = (max_reseed / 4) * 3
	endif

	conf_data.set('ESDM_DRNG_RESEED_THRESH_BITS', reseed_thresh)
	conf_data.set('ESDM_DRNG_MAX_RESEED_BITS', max_reseed)
else
	conf_data.set('ESDM_DRNG_RESEED_THRESH_BITS', get_option('drng_reseed_threshold_bits'))
	conf_data.set('ESDM_DRNG_MAX_RESEED_BITS', get_option('drng_max_reseed_bits'))
endif

conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_UNPRIVILEGED', get_option('esdm-server-rpc-path-unprivileged'))
conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_PRIVILEGED', get_option('esdm-server-rpc-path-privileged'))

# Default socket of the optional EGD interface: where the esdm-server-egd.socket
# unit places it, and therefore where an EGD client looks for it unless it is
# told otherwise.
conf_data.set_quoted('ESDM_SERVER_EGD_SOCKET_PATH', get_option('esdm-server-egd-socket-path'))

conf_data.set('ESDM_RPC_IDLE_TIMEOUT_USEC', get_option('esdm-server-rpc-idle-timeout-usec'))

# The io_uring event loop of the RPC server, see rpc-io-uring
conf_data.set('ESDM_RPC_IO_URING', rpc_io_uring)
conf_data.set('ESDM_RPC_IO_URING_MULTISHOT', rpc_io_uring_multishot)

conf_data.set('ESDM_HAS_AUX_CLIENT', get_option('esdm-aux-client').enabled())

conf_data.set('ESDM_NUM_AUX_POOLS', get_option('num-aux-pools'))
conf_data.set('ESDM_AUX_INPUT_HAS_FULL_ENTROPY', get_option('aux-has-full-entropy').enabled())

conf_data.set('ESDM_MEMORY_DEBUG', get_option('memory-debug').enabled())

# fips_enabled() trusts ESDM_SERVER_FORCE_FIPS only through secure_getenv(),
# which also refuses it to a binary gaining privileges through file capabilities
conf_data.set('HAVE_SECURE_GETENV',
	      cc.has_function('secure_getenv',
			      prefix: '#define _GNU_SOURCE\n#include <stdlib.h>'))

# Guards the entry points the fuzz harnesses drive the RPC interfaces
# through - see tests/fuzz. Left out of config.h rather than #undef'd there
# without the option: the regression tests in tests/fuzz compile the sources
# they test with -DESDM_FUZZING, which an #undef would take back.
if get_option('fuzzing').enabled()
	conf_data.set('ESDM_FUZZING', true)
endif

configure_file(output: 'config.h', configuration : conf_data)
