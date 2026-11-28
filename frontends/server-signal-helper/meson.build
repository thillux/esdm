# The resume notification is a reseed over the privileged RPC interface or, in
# a build without it, over the EGD interface. The suspend notification is a
# signal and needs neither.
if get_option('esdm-server-rpc').enabled()
	esdm_server_signal_helper_lib = esdm_rpc_client_lib
else
	esdm_server_signal_helper_lib = esdm_egd_client_lib
endif

esdm_server_signal_helper = executable(
		'esdm-server-signal-helper',
		[ 'server_signal_helper.c' ],
		include_directories: include_dirs_client,
        dependencies: [ dependencies_client ],
		link_with: esdm_server_signal_helper_lib,
		install: true
		)

esdm_server_suspend_service = configure_file(
	input : 'esdm-server-suspend.service.in',
	output : 'esdm-server-suspend.service',
	configuration : server_conf_data)
esdm_server_resume_service = configure_file(
	input : 'esdm-server-resume.service.in',
	output : 'esdm-server-resume.service',
	configuration : server_conf_data)

install_data(esdm_server_suspend_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
install_data(esdm_server_resume_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
