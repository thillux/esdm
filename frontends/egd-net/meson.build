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

# A client of an esdm-egd-net-server, by the EGD client library; the
# accounting of the local peers and the creation of the socket are those of
# the esdm-server.
esdm_egd_net_relay = executable('esdm-egd-net-relay',
	[ 'esdm_egd_net_relay.c', egd_net_common_src, egd_serve_src,
	  egd_net_privileges_src,
	  '../../service-egd/server/esdm_peer_account.c',
	  '../../service-egd/server/esdm_peer_limit.c',
	  '../../service-egd/server/esdm_server_socket.c' ],
	c_args: [ egd_net_version_arg ],
	include_directories: include_dirs_egd_net,
	dependencies: [ dependency('threads') ] + egd_net_tls_deps,
	link_with: [ esdm_egd_client_linked_lib, esdm_common_static_lib ],
	install: true
	)

# The CRLs, downloaded by a timer of their own - see the CRL UPDATES section of
# esdm-egd-net-server(8). No HTTP client in the daemons.
install_data('esdm-egd-net-crl-update.sh',
	rename: 'esdm-egd-net-crl-update',
	install_dir: get_option('libexecdir'),
	install_mode: 'rwxr-xr-x')

egd_net_conf_data = configuration_data()
egd_net_conf_data.set('PATH', get_option('prefix') / get_option('bindir'))
egd_net_conf_data.set('LIBEXECDIR',
		      get_option('prefix') / get_option('libexecdir'))
egd_net_conf_data.set('PORT', get_option('egd-net-port'))
# The consumers find the socket of the relay where they look for the ESDM's
egd_net_conf_data.set('SOCKET_PATH', get_option('esdm-server-egd-socket-path'))
egd_net_conf_data.set('SERVICE_TYPE', get_option('systemd').enabled() ?
					      'Type=notify' : 'Type=simple')

foreach unit : [ 'esdm-egd-net-server.service', 'esdm-egd-net-server.socket',
		 'esdm-egd-net-relay.service', 'esdm-egd-net-relay.socket',
		 'esdm-egd-net-crl-update@.service' ]
	install_data(configure_file(
			input: unit + '.in',
			output: unit,
			configuration: egd_net_conf_data),
		     install_dir: get_option('prefix') / 'lib/systemd/system')
endforeach
install_data('esdm-egd-net-crl-update@.timer',
	     install_dir: get_option('prefix') / 'lib/systemd/system')
