/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * The part of the ESDM's EGD protocol the module speaks
 *
 * A copy of what service-egd/esdm_egd_protocol.h of the ESDM defines, which
 * stays the reference: the module is built out of tree on its own, without
 * the ESDM sources. Keep the two in sync.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#ifndef ESDM_CDEV_EGD_PROTOCOL_H
#define ESDM_CDEV_EGD_PROTOCOL_H

#include <linux/bits.h>

/* Standard EGD commands */
#define ESDM_EGD_CMD_ENTROPY_COUNT 0x00
#define ESDM_EGD_CMD_READ_NONBLOCK 0x01
#define ESDM_EGD_CMD_WRITE_ENTROPY 0x03

/* ESDM extensions, all numbers big endian */
#define ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK 0xe0
#define ESDM_EGD_CMD_ESDM_READ_UNSEEDED 0xe2
#define ESDM_EGD_CMD_ESDM_GET_STATE 0xe3
#define ESDM_EGD_CMD_ESDM_STATUS 0xe4
#define ESDM_EGD_CMD_ESDM_STATUS_JSON 0xe5
#define ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT 0xe6
#define ESDM_EGD_CMD_ESDM_CLEAR_POOL 0xe7
#define ESDM_EGD_CMD_ESDM_RESEED 0xe8
#define ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP 0xe9
#define ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS 0xea

/* Fields of the answer to ESDM_EGD_CMD_ESDM_GET_STATE */
#define ESDM_EGD_STATE_FLAGS 0
#define ESDM_EGD_STATE_ENT_CNT 1
#define ESDM_EGD_STATE_POOLSIZE 2
#define ESDM_EGD_STATE_WRITE_WAKEUP 3
#define ESDM_EGD_STATE_MIN_RESEED_SECS 4
#define ESDM_EGD_STATE_NUM_FIELDS 5

#define ESDM_EGD_STATE_FLAG_OPERATIONAL BIT(0)
#define ESDM_EGD_STATE_FLAG_FULLY_SEEDED BIT(1)

/* Largest status report of ESDM_EGD_CMD_ESDM_STATUS and _STATUS_JSON */
#define ESDM_EGD_MAX_STATUS 65536

/* The protocol's length byte caps every transfer at 255 bytes. */
#define ESDM_EGD_MAX_TRANSFER 255

#endif /* ESDM_CDEV_EGD_PROTOCOL_H */
