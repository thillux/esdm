# Client for the EGD interface of the ESDM. Deliberately dependency free
# beyond the ESDM logger: everything it needs is one Unix domain stream
# socket, which is what makes it usable where the RPC client is not - in a
# process confined by seccomp as well. The TLS mode of the network -
# egd-net-tls - takes the TLS stack of the crypto backend, which the library
# therefore does not link: it loads it with a module of its own when a client
# in TLS mode is allocated, see esdm_egd_client_tls.h.
egd_client_src = files([
	'esdm_egd_client.c'
])

# Restrict the exports to the API - see version.lds, and esdm/meson.build on
# the probe.
esdm_egd_client_version_lds = meson.current_source_dir() / 'version.lds'
esdm_egd_client_link_args = [
	'-Wl,--version-script,' + esdm_egd_client_version_lds
]
if not cc.has_multi_link_arguments(esdm_egd_client_link_args)
	warning('Linker does not support version scripts - libesdm_egd_client.so exports every DSO_PUBLIC symbol')
	esdm_egd_client_link_args = []
endif

esdm_egd_client_lib = both_libraries('esdm_egd_client',
	[ egd_client_src ],
	c_args: egd_net_tls ? [ '-DESDM_EGD_CLIENT_TLS_MODULE' ] : [],
	include_directories: include_dirs_egd_client,
	dependencies: [ dl_dep ],
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_egd_client_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_egd_client_lib)

if egd_net_tls
	# The TLS module of the library: the TLS layer of the common library
	# and the TLS stack, behind a table of its functions.
	esdm_egd_tls_module_lds = meson.current_source_dir() / 'esdm_egd_tls_module.lds'
	esdm_egd_tls_module = shared_module('esdm-egd-tls',
		[ 'esdm_egd_client_tls.c' ],
		name_prefix: '',
		include_directories: include_dirs_egd_client,
		dependencies: [ dependency('threads') ] + egd_net_tls_deps,
		link_with: esdm_common_static_lib,
		link_args: cc.has_multi_link_arguments(
				'-Wl,--version-script,' + esdm_egd_tls_module_lds) ?
			[ '-Wl,--version-script,' + esdm_egd_tls_module_lds ] : [],
		link_depends: files('esdm_egd_tls_module.lds'),
		install: true,
		install_dir: get_option('libdir') / 'esdm'
		)

	# The client with the TLS layer linked in, for the daemons and the test
	# suite: a daemon has no sandbox to protect from its TLS stack.
	esdm_egd_client_linked_lib = static_library('esdm_egd_client_linked',
		[ egd_client_src ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_net_tls_deps,
		link_with: esdm_common_static_lib
		)
else
	esdm_egd_client_linked_lib = esdm_egd_client_lib.get_static_lib()
endif

include_user_files += files([
	'esdm_egd_client.h'
])
