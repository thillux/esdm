/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef ESDM_RPC_SERVICE_H
#define ESDM_RPC_SERVICE_H

#include <stdint.h>
#include <string.h>
#include <sys/ipc.h>

#include <stdatomic.h>
#include "config.h"
#include "esdm_rpc_protocol.h"
#include "priv_access.pb-c.h"
#include "test_pertubation.h"
#include "unpriv_access.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * IPC configuration
 ******************************************************************************/

#ifdef ESDM_TESTMODE

#define ESDM_RPC_UNPRIV_SOCKET "/tmp/esdm-rpc-unpriv-testmode.socket"

#define ESDM_RPC_PRIV_SOCKET "/tmp/esdm-rpc-priv-testmode.socket"

#define ESDM_SHM_NAME "/"
#define ESDM_SHM_STATUS 0x6573646d

#define ESDM_SEM_RANDOM_NAME "esdm-random-shm-status-semaphore-testmode"
#define ESDM_SEM_URANDOM_NAME "esdm-urandom-shm-status-semaphore-testmode"
#define ESDM_SEM_NEED_ENTROPY_LEVEL "esdm-need-entropy-level-semaphore-testmode"

#else /* ESDM_TESTMODE */

#define ESDM_RPC_UNPRIV_SOCKET                                                 \
	ESDM_SERVER_RPC_BASE_PATH_UNPRIVILEGED "/esdm-rpc-unpriv.socket"

#define ESDM_RPC_PRIV_SOCKET                                                   \
	ESDM_SERVER_RPC_BASE_PATH_PRIVILEGED "/esdm-rpc-priv.socket"

#define ESDM_SHM_NAME "/"
#define ESDM_SHM_STATUS 0x6d647365

#define ESDM_SEM_RANDOM_NAME "esdm-random-shm-status-semaphore"
#define ESDM_SEM_URANDOM_NAME "esdm-urandom-shm-status-semaphore"
#define ESDM_SEM_NEED_ENTROPY_LEVEL "esdm-need-entropy-level-semaphore"

#endif /* ESDM_TESTMODE */

/*
 * Name under which the esdm-cuse-random frontend registers its CUSE device -
 * the kernel creates the device node of that name below /dev - and the
 * resulting device path. The name is identical in test mode: only the
 * bind-mount target (/dev/random -> /dev/tst-random) is prefixed, not the
 * CUSE device itself.
 */
#define ESDM_CUSE_RANDOM_DEVNAME "esdm"
#define ESDM_CUSE_RANDOM_DEVICE "/dev/" ESDM_CUSE_RANDOM_DEVNAME

/* Same for the esdm-cuse-urandom frontend */
#define ESDM_CUSE_URANDOM_DEVNAME "uesdm"
#define ESDM_CUSE_URANDOM_DEVICE "/dev/" ESDM_CUSE_URANDOM_DEVNAME

#define ESDM_SHM_STATUS_VERSION 5

/*
 * Size of the rendered status report kept in the shared memory segment, and
 * of the status file of esdm-proc.
 *
 * esdm_status() prints the entropy sources first and the DRNG, reseed worker
 * and self test sections last, so a report cut short loses those. A build
 * with every source the ESDM has renders about 2700 bytes without the
 * entropy sources of the kernel, each of which adds about 160, PKCS#11 about
 * 200, and each external entropy source up to its ESDM_ES_EXT_STATUS_MAX
 * bytes of status: two of these took the report past the 4096 bytes this
 * was before. Four times that leaves room for sources yet to come. A report
 * longer still ends in a line saying so - see
 * esdm_shm_status_mark_truncated().
 *
 * Growing this changes the layout of struct esdm_shm_status, hence the version
 * bump above - an old client rejects the segment rather than misreading it.
 */
#define ESDM_SHM_STATUS_INFO_SIZE 16384

struct esdm_shm_status {
	/* Monotonic increasing version */
	uint32_t version;

	/* String with status information */
	char info[ESDM_SHM_STATUS_INFO_SIZE];
	/*
	 * Fixed width and no member aligned to more than 4 bytes: a 32-bit
	 * client attaches to the segment of a 64-bit server. With a size_t
	 * here, it read every member after this one 4 bytes off. Version 4.
	 */
	uint32_t infolen;

	/* Number of threads handling the unprivileged interface */
	uint32_t unpriv_threads;

	/* Is the ESDM operational? */
	atomic_bool operational;
	/* Do we need new entropy? */
	atomic_bool need_entropy;
	/*
	 * Bumped on a suspend/hibernate trigger and when the server exits. A
	 * counter rather than a flag a client clears: every CUSE daemon tracks
	 * the value it has seen on its own, so one of them cannot take the
	 * event away from another. Growing it to a counter is the bump of
	 * version 3.
	 */
	atomic_uint suspend_gen;
};

static inline key_t esdm_ftok(const char *pathname, int proj_id)
{
	return ftok(pathname, proj_id);
}

/*
 * End the text status report in @buf of @buflen bytes, which esdm_status() or
 * esdm_rpcc_status() cut short with -EMSGSIZE, after its last whole line that
 * leaves room for a line saying it is incomplete. The status segment and the
 * status file of esdm-proc have no return code to say so: their readers - the
 * CUSE ioctl 42, the aux client, a cat - would take the report as complete.
 */
static inline void esdm_shm_status_mark_truncated(char *buf, size_t buflen)
{
	static const char marker[] = "(status report truncated)\n";
	size_t len;
	char *nl;

	if (!buf || buflen < sizeof(marker))
		return;

	len = strnlen(buf, buflen - 1);
	if (len > buflen - sizeof(marker))
		len = buflen - sizeof(marker);
	buf[len] = '\0';

	nl = strrchr(buf, '\n');
	len = nl ? (size_t)(nl - buf) + 1 : 0;
	memcpy(buf + len, marker, sizeof(marker));
}

/******************************************************************************
 * Service functions wrapping the ESDM library
 *
 * For documentation, see the protobuf file
 ******************************************************************************/

void esdm_rpc_status(UnprivAccess_Service *service,
		     const StatusRequest *request,
		     StatusResponse_Closure closure, void *closure_data);

void esdm_rpc_status_json(UnprivAccess_Service *service,
			  const StatusRequest *request,
			  StatusResponse_Closure closure, void *closure_data);

void esdm_rpc_drng_status_json(UnprivAccess_Service *service,
			       const DrngStatusRequest *request,
			       StatusResponse_Closure closure,
			       void *closure_data);
void esdm_rpc_is_fully_seeded(UnprivAccess_Service *service,
			      const EmptyRequest *request,
			      IsFullySeededResponse_Closure closure,
			      void *closure_data);

void esdm_rpc_get_ent_lvl(UnprivAccess_Service *service,
			  const EmptyRequest *request,
			  ValResponse_Closure closure,
			  void *closure_data);

void esdm_rpc_get_random_bytes_full(UnprivAccess_Service *service,
				    const GetRandomBytesRequest *request,
				    RandValResponse_Closure closure,
				    void *closure_data);

void esdm_rpc_get_random_bytes_pr(UnprivAccess_Service *service,
				  const GetRandomBytesRequest *request,
				  RandValResponse_Closure closure,
				  void *closure_data);

void esdm_rpc_get_random_bytes(UnprivAccess_Service *service,
			       const GetRandomBytesRequest *request,
			       RandValResponse_Closure closure,
			       void *closure_data);

void esdm_rpc_get_seed(UnprivAccess_Service *service,
		       const GetSeedRequest *request,
		       RandValResponse_Closure closure, void *closure_data);

void esdm_rpc_write_data(UnprivAccess_Service *service,
			 const WriteDataRequest *request,
			 RetResponse_Closure closure, void *closure_data);

/* IOCTL implementations */
void esdm_rpc_rnd_get_ent_cnt(UnprivAccess_Service *service,
			      const EmptyRequest *request,
			      ValResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_add_to_ent_cnt(PrivAccess_Service *service,
				 const RndAddToEntCntRequest *request,
				 RetResponse_Closure closure,
				 void *closure_data);
void esdm_rpc_rnd_add_entropy(PrivAccess_Service *service,
			      const RndAddEntropyRequest *request,
			      RetResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_clear_pool(PrivAccess_Service *service,
			     const EmptyRequest *request,
			     RetResponse_Closure closure,
			     void *closure_data);
void esdm_rpc_rnd_reseed_crng(PrivAccess_Service *service,
			      const EmptyRequest *request,
			      RetResponse_Closure closure,
			      void *closure_data);

/* /proc implementations */
void esdm_rpc_get_poolsize(UnprivAccess_Service *service,
			   const EmptyRequest *request,
			   ValResponse_Closure closure,
			   void *closure_data);
void esdm_rpc_get_write_wakeup_thresh(
	UnprivAccess_Service *service,
	const EmptyRequest *request,
	ValResponse_Closure closure, void *closure_data);
void esdm_rpc_set_write_wakeup_thresh(
	PrivAccess_Service *service, const SetWriteWakeupThreshRequest *request,
	RetResponse_Closure closure, void *closure_data);
void esdm_rpc_get_min_reseed_secs(UnprivAccess_Service *service,
				  const EmptyRequest *request,
				  ValResponse_Closure closure,
				  void *closure_data);
void esdm_rpc_set_min_reseed_secs(PrivAccess_Service *service,
				  const SetMinReseedSecsRequest *request,
				  RetResponse_Closure closure,
				  void *closure_data);

/* entropy source specific implementations */
void esdm_rpc_jent_status(UnprivAccess_Service *service,
			  const StatusRequest *request,
			  StatusResponse_Closure closure,
			  void *closure_data);

/* the reserved slot of the PKCS#11 configuration, see priv_access.proto */
void esdm_rpc_reserved_set_pkcs11_config(PrivAccess_Service *service,
					 const EmptyRequest *request,
					 RetResponse_Closure closure,
					 void *closure_data);

/* self tests */
void esdm_rpc_selftest(PrivAccess_Service *service, const EmptyRequest *request,
		       SelftestResponse_Closure closure, void *closure_data);

/******************************************************************************
 * Definition of Protobuf-C service
 ******************************************************************************/

extern UnprivAccess_Service unpriv_access_service;
extern PrivAccess_Service priv_access_service;

/******************************************************************************
 * Common Helper
 ******************************************************************************/

/*
 * Initially it should have been 65536, but somehow protobuf-c has some
 * additional meta data along with the buffer and has an internal limit. This
 * causes a hang when choosing a value > 65512. To be a bit more conservative
 * let us pick a value with some more leeway.
 */
#define ESDM_RPC_MAX_MSG_SIZE 65536
#define ESDM_RPC_MAX_RPC_HEADER_SIZE sizeof(struct esdm_rpc_proto_sc_header)
#define ESDM_RPC_MAX_INTERNAL_MSG_HEADER_SIZE sizeof(uint64_t)
#define ESDM_RPC_MAX_INTERNAL_MSG_SIZE                                         \
	(ESDM_RPC_MAX_MSG_SIZE - ESDM_RPC_MAX_RPC_HEADER_SIZE)
#define ESDM_RPC_MAX_DATA                                                      \
	(ESDM_RPC_MAX_INTERNAL_MSG_SIZE - ESDM_RPC_MAX_INTERNAL_MSG_HEADER_SIZE)

/*
 * Largest status report, including its terminating NUL, that a StatusResponse
 * carries within ESDM_RPC_MAX_INTERNAL_MSG_SIZE. Next to the text, the message
 * holds its ret field - a tag and, for a negative value such as the -EMSGSIZE
 * of a truncated report, a 10 byte varint - and the tag and 3 byte length of
 * the string. ESDM_RPC_MAX_DATA does not leave room for all of that.
 */
#define ESDM_RPC_MAX_STATUS_DATA                                               \
	(ESDM_RPC_MAX_INTERNAL_MSG_SIZE - (1 + 10) - (1 + 3) + 1)

/*
 * Scratch buffer size for unpacking a received protobuf message with the
 * esdm_rpc_alloc() bump allocator instead of malloc()/free() on every call.
 * It must hold the unpacked message struct plus the largest possible
 * variable-length field (up to ESDM_RPC_MAX_DATA) plus per-allocation
 * alignment padding, hence the headroom over the raw wire message size.
 */
#define ESDM_RPC_MAX_UNPACK_SIZE (ESDM_RPC_MAX_MSG_SIZE + 1024)

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_SERVICE_H */
