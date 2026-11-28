# The EGD (Entropy Gathering Daemon) compatibility interface of the ESDM.
#
# Laid out like service-rpc: the protocol definition next to this file is
# shared by both sides, the client below is a standalone library and the server
# contributes its sources to the esdm-server binary.
#
# Left out of the build with esdm-server-egd disabled. The targets that list
# the server sources next to those of the RPC interface then add nothing.
if get_option('esdm-server-egd').enabled()
	subdir('client')
	subdir('server')

	include_user_files += files([
		'esdm_egd_protocol.h'
	])
else
	egd_server_src = []
endif
