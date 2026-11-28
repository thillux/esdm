# The wire protocol and the protobuf services of the RPC interface. Left out of
# the build with esdm-server-rpc disabled; the header esdm_rpc_service.h with
# the names of the status segment and its semaphores is used either way.
#
# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('esdm-server-rpc').enabled()
	service_rpc_src = files([
		'esdm_rpc_protocol_helper.c',
		'esdm_rpc_protocol.c',
		'common.pb-c.c',
		'priv_access.pb-c.c',
		'unpriv_access.pb-c.c',
	])
else
	service_rpc_src = []
endif
