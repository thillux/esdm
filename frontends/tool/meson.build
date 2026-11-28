esdm_tool_src = [
	'tool_main.c',
	'common.c',
	'stress_delay.c',
	'stress_process.c',
	'stress_thread.c',
]

# The interface of the server the tool works over, see backend.h: the RPC
# interface where it is part of the build, else the EGD interface.
if get_option('esdm-server-rpc').enabled()
	esdm_tool_src += [
		'backend_rpc.c',
		# The reference counting of libesdm_rpc_client
		'stress_init_fini.c',
	]
	esdm_tool_backend_lib = esdm_rpc_client_lib
else
	esdm_tool_src += [ 'backend_egd.c' ]
	esdm_tool_backend_lib = esdm_egd_client_lib
endif

esdm_tool = executable(
		'esdm-tool',
		esdm_tool_src,
		include_directories: [ include_dirs_client, include_dirs_aux_client ],
		dependencies: [ dependencies_client, json_c_dep ],
		link_with:  [ esdm_common_static_lib, esdm_tool_backend_lib ] + (get_option('esdm-aux-client').enabled() ? [esdm_aux_client_lib] : []),
		install: true
		)

tool_wait_conf_data = configuration_data()
tool_wait_conf_data.set('PATH', get_option('prefix') + '/' + get_option('bindir'))
tool_wait_service = configure_file(
	input : 'esdm-wait-until-fully-seeded.service.in',
	output : 'esdm-wait-until-fully-seeded.service',
	configuration : tool_wait_conf_data)
install_data(tool_wait_service,
	install_dir: get_option('prefix') / 'lib/systemd/system')
