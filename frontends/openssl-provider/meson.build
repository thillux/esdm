# Shared by every provider below, whatever its backend is.
openssl_provider_shared_src = [
	'prov_error.c'
]

# The RPC based providers additionally share their whole implementation; only
# the table of offered algorithms differs between them.
openssl_provider_src = [
	'common.c'
] + openssl_provider_shared_src

# Every provider exports its entry point and nothing else - see version.lds,
# and esdm/meson.build on the probe.
openssl_provider_version_lds = meson.current_source_dir() / 'version.lds'
openssl_provider_link_args = [
	'-Wl,--version-script,' + openssl_provider_version_lds
]
if not cc.has_multi_link_arguments(openssl_provider_link_args)
	warning('Linker does not support version scripts - the OpenSSL providers export every DSO_PUBLIC symbol')
	openssl_provider_link_args = []
endif

esdm_openssl_rng_provider_lib = library(
	'esdm-rng-provider',
	[
		'rng-provider.c',
		openssl_provider_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	link_args: openssl_provider_link_args,
	link_depends: files('version.lds'),
	install: true
)
pkgconfig.generate(esdm_openssl_rng_provider_lib)

# Variant that defaults all generate / get_seed calls to the prediction
# resistance RPC (esdm_rpcc_get_random_bytes_pr) regardless of the
# prediction_resistance flag passed in by OpenSSL.
esdm_openssl_rng_provider_pr_lib = library(
	'esdm-rng-provider-pr',
	[
		'rng-provider.c',
		openssl_provider_src
	],
	c_args: [
		'-DESDM_OSSL_PROV_FORCE_PR=1',
		'-DESDM_PROV_NAME="ESDM RNG Provider (PR)"',
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	link_args: openssl_provider_link_args,
	link_depends: files('version.lds'),
	install: true
)
pkgconfig.generate(esdm_openssl_rng_provider_pr_lib)

# Variant talking the EGD protocol instead of the ESDM RPC: a single Unix
# domain stream socket, neither the RPC client library nor the two RPC sockets,
# which makes it usable where the RPC interface cannot be reached. Its
# algorithms carry "provider=esdm-egd" to tell them apart from the RPC ones.
esdm_openssl_egd_provider_lib = library(
	'esdm-egd-provider',
	[
		'egd-provider.c',
		openssl_provider_shared_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	# The EGD client, not the RPC client the other providers pull in.
	link_with: esdm_egd_client_lib.get_static_lib(),
	link_args: openssl_provider_link_args,
	link_depends: files('version.lds'),
	install: true
)
pkgconfig.generate(esdm_openssl_egd_provider_lib)

# Variant serving every request from the prediction resistance DRNG, over the
# same EGD socket with the ESDM's prediction resistant read command, whatever
# the prediction_resistance flag passed in by OpenSSL. Its algorithms carry
# "provider=esdm-egd-pr".
esdm_openssl_egd_provider_pr_lib = library(
	'esdm-egd-provider-pr',
	[
		'egd-provider.c',
		openssl_provider_shared_src
	],
	c_args: [
		'-DESDM_EGD_PROV_FORCE_PR=1',
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_egd_client_lib.get_static_lib(),
	link_args: openssl_provider_link_args,
	link_depends: files('version.lds'),
	install: true
)
pkgconfig.generate(esdm_openssl_egd_provider_pr_lib)

esdm_openssl_seed_src_provider_lib = library(
	'esdm-seed-src-provider',
	[
		'seed-src-provider.c',
		openssl_provider_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	link_args: openssl_provider_link_args,
	link_depends: files('version.lds'),
	install: true
)
pkgconfig.generate(esdm_openssl_seed_src_provider_lib)
