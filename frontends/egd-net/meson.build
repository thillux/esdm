# The EGD protocol over the network: the esdm-egd-net-server serving it to
# the hosts of a network, and the esdm-egd-net-relay serving the EGD socket of
# a host without an ESDM through such a server - see their man pages.
include_dirs_egd_net = include_directories([
	'.',
	'../../common',
	'../../service-egd',
	'../../service-egd/client',
	'../../service-egd/serve',
	'../../service-egd/server',
	'../../service-rpc/client',
	'../../service-rpc/server',
	'../../service-rpc/service',
])

egd_net_version_arg = '-DESDM_EGD_NET_VERSION="' + meson.project_version() + '"'

egd_net_common_src = files([ 'egd_net_common.c' ])

# The privilege drop is the esdm-server's, see privileges.h
egd_net_privileges_src = files([ '../../service-rpc/server/privileges.c' ])

# A client of the unprivileged RPC interface, nothing more: the RPC client
# and the common code, statically, so that the logger exists once.
esdm_egd_net_server = executable('esdm-egd-net-server',
	[ 'esdm_egd_net_server.c', egd_net_common_src, egd_serve_src,
	  egd_net_privileges_src ],
	c_args: [ egd_net_version_arg ],
	include_directories: include_dirs_egd_net,
	dependencies: [ dependencies_client, json_c_dep ],
	link_with: [ esdm_rpc_client_lib.get_static_lib(),
		     esdm_common_static_lib ],
	install: true
	)
