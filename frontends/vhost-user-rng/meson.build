# esdm-vhost-user-rng: the vhost-user back-end of a virtio entropy device, a
# process of its own per VM that reaches the ESDM through the unprivileged RPC
# interface - see esdm-vhost-user-rng(8).
#
# The protocol and ring handling is a library of its own, so the tests can
# drive it with a random source of their own; the fuzz harnesses compile its
# sources instead, to have them instrumented.
vhost_user_rng_core_src = files([
	'vhost_user_dev.c',
	'vhost_user_mem.c',
	'vhost_user_vring.c',
])

vhost_user_rng_inc = include_directories([
	'.',
	'../../service-egd/server',
	'../../service-rpc/server',
])

vhost_user_rng_core_lib = static_library('vhost_user_rng_core',
		vhost_user_rng_core_src,
		include_directories: [ include_dirs_client, vhost_user_rng_inc ],
		dependencies: [ dependencies_client ],
		link_with: [ esdm_common_static_lib ],
		)

esdm_vhost_user_rng = executable(
		'esdm-vhost-user-rng',
		[ 'vhost_user_rng.c',
		  '../../service-egd/server/esdm_server_socket.c',
		  '../../service-rpc/server/privileges.c' ],
		include_directories: [ include_dirs_client, vhost_user_rng_inc ],
		dependencies: [ dependencies_client ],
		link_with: [ vhost_user_rng_core_lib, esdm_common_static_lib,
			     esdm_rpc_client_lib ],
		install: true
		)

vhost_user_rng_conf_data = configuration_data()
vhost_user_rng_conf_data.set('PATH', get_option('prefix') / get_option('bindir'))
vhost_user_rng_conf_data.set('SOCKET_GROUP', get_option('vhost-user-rng-socket-group'))

foreach unit : [ 'esdm-vhost-user-rng@.socket', 'esdm-vhost-user-rng@.service' ]
	install_data(configure_file(
			input : unit + '.in',
			output : unit,
			configuration : vhost_user_rng_conf_data),
		     install_dir: get_option('prefix') / 'lib/systemd/system')
endforeach
