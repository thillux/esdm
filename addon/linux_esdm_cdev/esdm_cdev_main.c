// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>

#include "esdm_cdev.h"

static int __init esdm_cdev_init(void)
{
	return esdm_cdev_egd_init();
}

/* Only once nobody uses the module any more */
static void __exit esdm_cdev_exit(void)
{
	esdm_cdev_egd_fini();
}

module_init(esdm_cdev_init);
module_exit(esdm_cdev_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Markus Theil <theil.markus@gmail.com>");
MODULE_DESCRIPTION("ESDM character device frontend");
