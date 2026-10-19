/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM character device frontend - internal interfaces
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#ifndef ESDM_CDEV_H
#define ESDM_CDEV_H

#include <linux/types.h>
#include <linux/uio.h>

#include "esdm_egd_protocol.h"

/* State of the ESDM as the answer to ESDM_EGD_CMD_ESDM_GET_STATE reports it */
struct esdm_cdev_state {
	u32 flags;
	u32 ent_cnt;
	u32 poolsize;
	u32 write_wakeup;
	u32 min_reseed_secs;
};

/* EGD client, esdm_cdev_egd.c */
int esdm_cdev_egd_init(void);
void esdm_cdev_egd_fini(void);

/* Read commands sent together, and the bytes they ask for at most */
#define ESDM_CDEV_READ_CMDS 16
#define ESDM_CDEV_READ_MAX (ESDM_CDEV_READ_CMDS * ESDM_EGD_MAX_TRANSFER)

/*
 * Read up to @len bytes, at most ESDM_CDEV_READ_MAX, with the read command
 * @cmd, which answers with a length byte and that many bytes. Returns the
 * number of bytes delivered, which may be fewer than asked for, or a negative
 * errno: -ERESTARTSYS when a signal interrupted the caller, any other when the
 * ESDM could not be asked.
 */
int esdm_cdev_egd_read(u8 cmd, u8 *buf, size_t len);

/*
 * Insert @len bytes of user memory at @ubuf into the auxiliary pool of the
 * ESDM, without entropy credit. Returns the number of bytes inserted, fewer
 * than @len when user memory was not readable, a signal or an error of the
 * ESDM came after some of them; without any, -EFAULT when user memory was not
 * readable, or another negative errno when the ESDM could not be reached.
 */
ssize_t esdm_cdev_egd_insert_user(const char __user *ubuf, size_t len);

int esdm_cdev_egd_get_state(struct esdm_cdev_state *state);

/*
 * The status report as text or JSON document (@json). On success, *@report
 * holds a NUL terminated copy of *@len bytes, to be released with kvfree().
 */
int esdm_cdev_egd_status(bool json, char **report, size_t *len);

/*
 * One of the privileged commands changing the entropy accounting or the
 * DRNGs, with its argument @arg if @has_arg. Returns the status the ESDM
 * answered with, or a negative errno when it could not be asked. Once sent,
 * the command is carried out by the ESDM, so it is never restarted: its answer
 * is waited for despite signals, -EINTR only for a fatal one. Only to be
 * invoked on behalf of a caller holding CAP_SYS_ADMIN.
 */
int esdm_cdev_egd_priv(u8 cmd, bool has_arg, u32 arg);

/*
 * Run @fn on the module's workqueue, in the file system context, namespaces
 * and with the credentials of init - see esdm_cdev_egd.c. @fn fills a buffer
 * of @reslen bytes, which is copied to @res once @fn returned 0 within
 * @timeout_ms. A result nobody waits for any more is handed to @discard, if
 * given, to release what it holds. Returns what @fn returned, -ETIMEDOUT,
 * -ERESTARTSYS, or -ENOMEM.
 */
int esdm_cdev_run_in_init(int (*fn)(void *out), void (*discard)(void *out),
			  void *res, size_t reslen, unsigned int timeout_ms);

/* /proc/esdm, esdm_cdev_proc.c */
int esdm_cdev_proc_init(void);
void esdm_cdev_proc_fini(void);

#endif /* ESDM_CDEV_H */
