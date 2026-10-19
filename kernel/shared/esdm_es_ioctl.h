/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * IOCTL interface of /dev/esdm_es
 *
 * The ABI between the kernel module esdm_es (kernel/esdm_es) and the
 * interrupt and scheduler entropy sources of the ESDM (esdm/es/esdm_es_irq.c,
 * esdm/es/esdm_es_sched.c), included by both.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_IOCTL_H
#define _ESDM_ES_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ESDMIO 0xE0

/*
 * The entropy buffer read by ESDM_IRQ_ENT_BUF / ESDM_SCHED_ENT_BUF holds the
 * seed size the module is built for, and its size is part of the IOCTL
 * number: the ESDM asks for the size with ESDM_*_ENT_BUF_SIZE and reads with
 * the IOCTL of the entropy buffer of that size, ESDM_*_ENT_BUF_IOCTL(type).
 */

/* IRQ ES: return available entropy */
#define ESDM_IRQ_AVAIL_ENTROPY _IOR(ESDMIO, 0x00, __u32)

/* IRQ ES: return size of entropy buffer struct and ES number */
#define ESDM_IRQ_ENT_BUF_SIZE _IOR(ESDMIO, 0x01, __u32[2])

/* IRQ ES: read entropy value into the entropy buffer @type */
#define ESDM_IRQ_ENT_BUF_IOCTL(type) _IOR(ESDMIO, 0x02, type)

/*
 * IRQ ES: configure entropy source with the following protocol
 *
 * 1. When writing 2 * sizeof(u32): the first 4 bits are interpreted as a bit
 *    field with:
 * 	ESDM_ES_MGR_RESET_BIT set -> reset entropy source
 * 	ESDM_ES_MGR_REQ_BITS_MASK: amount of requested entropy in bits
 *    The second 4 bits are interpreted as entropy rate.
 *
 * Any other value is treated as an error.
 */
#define ESDM_IRQ_CONF _IOW(ESDMIO, 0x03, __u32[2])

/* IRQ ES: read status information */
#define ESDM_IRQ_STATUS _IOR(ESDMIO, 0x04, char[250])

/* SCHED ES: return available entropy */
#define ESDM_SCHED_AVAIL_ENTROPY _IOR(ESDMIO, 0x05, __u32)

/* SCHED ES: return size of entropy buffer struct and ES number */
#define ESDM_SCHED_ENT_BUF_SIZE _IOR(ESDMIO, 0x06, __u32[2])

/* SCHED ES: read entropy value into the entropy buffer @type */
#define ESDM_SCHED_ENT_BUF_IOCTL(type) _IOR(ESDMIO, 0x07, type)

/*
 * SCHED ES: configure entropy source with the same protocol as
 * ESDM_IRQ_CONF
 */
#define ESDM_SCHED_CONF _IOW(ESDMIO, 0x08, __u32[2])

/* SCHED ES: read status information */
#define ESDM_SCHED_STATUS _IOR(ESDMIO, 0x09, char[250])

/*
 * IRQ / SCHED ES: read status information as a JSON object
 *
 * The returned document carries the same properties as the plain status text
 * of ESDM_IRQ_STATUS / ESDM_SCHED_STATUS with the labels turned into JSON
 * member names, so that the ESDM server can embed it in its JSON status
 * document without parsing text.
 */
#define ESDM_IRQ_STATUS_JSON _IOR(ESDMIO, 0x0a, char[500])
#define ESDM_SCHED_STATUS_JSON _IOR(ESDMIO, 0x0b, char[500])

/* Size of the buffer the JSON status IOCTLs report into */
#define ESDM_STATUS_JSON_BUFLEN 500

/* The bits of the first word of ESDM_IRQ_CONF / ESDM_SCHED_CONF */
/* low 9 bits - can set 512 bits of entropy max */
#define ESDM_ES_MGR_REQ_BITS_MASK 0x1ff
#define ESDM_ES_MGR_RESET_BIT 0x80000000

#endif /* _ESDM_ES_IOCTL_H */
