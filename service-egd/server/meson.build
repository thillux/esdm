# Server side of the EGD interface. Unlike the client it is not a library of
# its own: it is part of the esdm-server, whose RPC server drives its lifecycle
# (socket setup before the privilege drop, worker afterwards). The per-user
# accounting and the socket creation are shared with the RPC server.
egd_server_src = files([
	'esdm_egd_server.c',
	'esdm_peer_account.c',
	'esdm_peer_limit.c',
	'esdm_server_socket.c'
])
