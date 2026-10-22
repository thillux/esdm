/*
 * Linker version script for the OpenSSL providers.
 *
 * OpenSSL loads a provider with dlopen() and only ever looks up its entry
 * point. Everything else is hidden - in particular what the providers pull in
 * from static ESDM libraries, the EGD client, the logger and the thread pool.
 * Exported, those would be bound to whatever definition of the same name the
 * process already has, such as a libesdm_egd_client.so of a different
 * version the application links itself.
 */

{
	global:
		OSSL_provider_init;

	local:
		*;
};
