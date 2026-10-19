# The EGD (Entropy Gathering Daemon) compatibility interface of the ESDM.
#
# Laid out like service-rpc: the protocol definition next to this file is
# shared by both sides, the client below is a standalone library and the server
# contributes its sources to the esdm-server binary. The serving loop of serve/
# is that of the daemons serving the protocol outside the esdm-server.
subdir('client')
subdir('server')
subdir('serve')

include_user_files += files([
	'esdm_egd_protocol.h'
])
