// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM testing interfaces to obtain raw entropy
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/errno.h>

#include "esdm_testing.h"

#if defined(CONFIG_LRNG_RAW_SCHED_HIRES_ENTROPY) ||		\
    defined(CONFIG_LRNG_RAW_SCHED_PID_ENTROPY) ||		\
    defined(CONFIG_LRNG_RAW_SCHED_START_TIME_ENTROPY) ||	\
    defined(CONFIG_LRNG_RAW_SCHED_NVCSW_ENTROPY) ||		\
    defined(CONFIG_LRNG_SCHED_PERF)
#define LRNG_TESTING_USE_BUSYLOOP
#endif

#define ESDM_TESTING_RINGBUFFER_SIZE	1024
#define ESDM_TESTING_RINGBUFFER_MASK	(ESDM_TESTING_RINGBUFFER_SIZE - 1)

struct esdm_testing {
	u32 esdm_testing_rb[ESDM_TESTING_RINGBUFFER_SIZE];
	u32 rb_reader;
	atomic_t rb_writer;
	atomic_t esdm_testing_enabled;
	spinlock_t lock;
	wait_queue_head_t read_wait;
};

/*************************** Generic Data Handling ****************************/

/*
 * boot variable:
 * 0 ==> No boot test, gathering of runtime data allowed
 * 1 ==> Boot test enabled and ready for collecting data, gathering runtime
 *	 data is disabled
 * 2 ==> Boot test completed and disabled, gathering of runtime data is
 *	 disabled
 */

static void esdm_testing_reset(struct esdm_testing *data)
{
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	data->rb_reader = 0;
	atomic_set(&data->rb_writer, 0);
	spin_unlock_irqrestore(&data->lock, flags);
}

static void esdm_testing_init(struct esdm_testing *data, u32 boot)
{
	/*
	 * The boot time testing implies we have a running test. If the
	 * caller wants to clear it, he has to unset the boot_test flag
	 * at runtime via sysfs to enable regular runtime testing
	 */
	if (boot)
		return;

	esdm_testing_reset(data);
	atomic_set(&data->esdm_testing_enabled, 1);
	pr_warn("Enabling data collection\n");
}

static void esdm_testing_fini(struct esdm_testing *data, u32 boot)
{
	/* If we have boot data, we do not reset yet to allow data to be read */
	if (boot)
		return;

	atomic_set(&data->esdm_testing_enabled, 0);
	esdm_testing_reset(data);
	pr_warn("Disabling data collection\n");
}

static bool esdm_testing_store(struct esdm_testing *data, u32 value,
			       u32 *boot)
{
	unsigned long flags;

	if (!atomic_read(&data->esdm_testing_enabled) && (*boot != 1))
		return false;

	spin_lock_irqsave(&data->lock, flags);

	/*
	 * Disable entropy testing for boot time testing after ring buffer
	 * is filled.
	 */
	if (*boot) {
		if (((u32)atomic_read(&data->rb_writer)) >
		    ESDM_TESTING_RINGBUFFER_SIZE) {
			*boot = 2;
			pr_warn_once("One time data collection test disabled\n");
			spin_unlock_irqrestore(&data->lock, flags);
			return false;
		}

		if (atomic_read(&data->rb_writer) == 1)
			pr_warn("One time data collection test enabled\n");
	}

	data->esdm_testing_rb[((u32)atomic_read(&data->rb_writer)) &
			      ESDM_TESTING_RINGBUFFER_MASK] = value;
	atomic_inc(&data->rb_writer);

	spin_unlock_irqrestore(&data->lock, flags);

#ifndef ESDM_TESTING_USE_BUSYLOOP
	if (wq_has_sleeper(&data->read_wait))
		wake_up_interruptible(&data->read_wait);
#endif

	return true;
}

static bool esdm_testing_have_data(struct esdm_testing *data)
{
	return ((((u32)atomic_read(&data->rb_writer)) &
		 ESDM_TESTING_RINGBUFFER_MASK) !=
		 (data->rb_reader & ESDM_TESTING_RINGBUFFER_MASK));
}

static int esdm_testing_reader(struct esdm_testing *data, u32 *boot,
			       u8 *outbuf, u32 outbuflen)
{
	unsigned long flags;
	int collected_data = 0;

	esdm_testing_init(data, *boot);

	while (outbuflen) {
		u32 writer = (u32)atomic_read(&data->rb_writer);

		spin_lock_irqsave(&data->lock, flags);

		/* We have no data or reached the writer. */
		if (!writer || (writer == data->rb_reader)) {

			spin_unlock_irqrestore(&data->lock, flags);

			/*
			 * Now we gathered all boot data, enable regular data
			 * collection.
			 */
			if (*boot) {
				*boot = 0;
				goto out;
			}

#ifdef ESDM_TESTING_USE_BUSYLOOP
			while (!esdm_testing_have_data(data))
				;
#else
			wait_event_interruptible(data->read_wait,
						 esdm_testing_have_data(data));
#endif
			if (signal_pending(current)) {
				collected_data = -ERESTARTSYS;
				goto out;
			}

			continue;
		}

		/* We copy out word-wise */
		if (outbuflen < sizeof(u32)) {
			spin_unlock_irqrestore(&data->lock, flags);
			goto out;
		}

		memcpy(outbuf, &data->esdm_testing_rb[data->rb_reader],
		       sizeof(u32));
		data->rb_reader++;

		spin_unlock_irqrestore(&data->lock, flags);

		outbuf += sizeof(u32);
		outbuflen -= sizeof(u32);
		collected_data += sizeof(u32);
	}

out:
	esdm_testing_fini(data, *boot);
	return collected_data;
}

static int esdm_testing_extract_user(struct file *file, char __user *buf,
				     size_t nbytes, loff_t *ppos,
				     int (*reader)(u8 *outbuf, u32 outbuflen))
{
	u8 *tmp, *tmp_aligned;
	int ret = 0, large_request = (nbytes > 256);

	if (!nbytes)
		return 0;

	/*
	 * The intention of this interface is for collecting at least
	 * 1000 samples due to the SP800-90B requirements. So, we make no
	 * effort in avoiding allocating more memory that actually needed
	 * by the user. Hence, we allocate sufficient memory to always hold
	 * that amount of data.
	 */
	tmp = kmalloc(ESDM_TESTING_RINGBUFFER_SIZE + sizeof(u32), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp_aligned = PTR_ALIGN(tmp, sizeof(u32));

	while (nbytes) {
		int i;

		if (large_request && need_resched()) {
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
			schedule();
		}

		i = min_t(int, nbytes, ESDM_TESTING_RINGBUFFER_SIZE);
		i = reader(tmp_aligned, i);
		if (i <= 0) {
			if (i < 0)
				ret = i;
			break;
		}
		if (copy_to_user(buf, tmp_aligned, i)) {
			ret = -EFAULT;
			break;
		}

		nbytes -= i;
		buf += i;
		ret += i;
	}

	kfree_sensitive(tmp);

	if (ret > 0)
		*ppos += ret;

	return ret;
}

/****** Raw High-Resolution Scheduler-based Timer Entropy Data Handling *******/

#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY

static u32 boot_raw_sched_hires_test = 0;
module_param(boot_raw_sched_hires_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_sched_hires_test, "Enable gathering boot time high resolution timer entropy of the first Scheduler-based entropy events");

static struct esdm_testing esdm_raw_sched_hires = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock      = __SPIN_LOCK_UNLOCKED(esdm_raw_sched_hires.lock),
	.read_wait =
		__WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_sched_hires.read_wait)
};

bool esdm_raw_sched_hires_entropy_store(u32 value)
{
	return esdm_testing_store(&esdm_raw_sched_hires, value,
				  &boot_raw_sched_hires_test);
}

static int esdm_raw_sched_hires_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_sched_hires,
				   &boot_raw_sched_hires_test,
				   outbuf, outbuflen);
}

static ssize_t esdm_raw_sched_hires_read(struct file *file, char __user *to,
					 size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_sched_hires_entropy_reader);
}

static const struct file_operations esdm_raw_sched_hires_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_sched_hires_read,
};

#endif /* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */

/******************** Interrupt Performance Data Handling *********************/

#ifdef CONFIG_ESDM_SCHED_PERF

static u32 boot_sched_perf = 0;
module_param(boot_sched_perf, uint, 0644);
MODULE_PARM_DESC(boot_sched_perf, "Enable gathering scheduler-based entropy source performance data");

static struct esdm_testing esdm_sched_perf = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock      = __SPIN_LOCK_UNLOCKED(esdm_sched_perf.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_sched_perf.read_wait)
};

bool esdm_sched_perf_time(u32 start)
{
	return esdm_testing_store(&esdm_sched_perf, random_get_entropy() - start,
				  &boot_sched_perf);
}

static int esdm_sched_perf_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_sched_perf, &boot_sched_perf, outbuf,
				   outbuflen);
}

static ssize_t esdm_sched_perf_read(struct file *file, char __user *to,
				    size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_sched_perf_reader);
}

static const struct file_operations esdm_sched_perf_fops = {
	.owner = THIS_MODULE,
	.read = esdm_sched_perf_read,
};

#endif /* CONFIG_ESDM_SCHED_PERF */

/*************** Raw Scheduler task_struct->pid Data Handling *****************/

#ifdef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY

static u32 boot_raw_sched_pid_test = 0;
module_param(boot_raw_sched_pid_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_sched_pid_test, "Enable gathering boot time entropy of the first PIDs collected by the scheduler entropy source");

static struct esdm_testing esdm_raw_sched_pid = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock      = __SPIN_LOCK_UNLOCKED(esdm_raw_sched_pid.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_sched_pid.read_wait)
};

bool esdm_raw_sched_pid_entropy_store(u32 value)
{
	return esdm_testing_store(&esdm_raw_sched_pid, value,
				  &boot_raw_sched_pid_test);
}

static int esdm_raw_sched_pid_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_sched_pid,
				   &boot_raw_sched_pid_test, outbuf, outbuflen);
}

static ssize_t esdm_raw_sched_pid_read(struct file *file, char __user *to,
				       size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_sched_pid_entropy_reader);
}

static const struct file_operations esdm_raw_sched_pid_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_sched_pid_read,
};

#endif /* CONFIG_ESDM_RAW_SCHED_PID_ENTROPY */


/*********** Raw Scheduler task_struct->start_time Data Handling **************/

#ifdef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY

static u32 boot_raw_sched_starttime_test = 0;
module_param(boot_raw_sched_starttime_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_sched_starttime_test, "Enable gathering boot time entropy of the first task start times collected by the scheduler entropy source");

static struct esdm_testing esdm_raw_sched_starttime = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock      = __SPIN_LOCK_UNLOCKED(esdm_raw_sched_starttime.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_sched_starttime.read_wait)
};

bool esdm_raw_sched_starttime_entropy_store(u32 value)
{
	return esdm_testing_store(&esdm_raw_sched_starttime, value,
				  &boot_raw_sched_starttime_test);
}

static int esdm_raw_sched_starttime_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_sched_starttime,
				   &boot_raw_sched_starttime_test, outbuf, outbuflen);
}

static ssize_t esdm_raw_sched_starttime_read(struct file *file, char __user *to,
				       size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_sched_starttime_entropy_reader);
}

static const struct file_operations esdm_raw_sched_starttime_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_sched_starttime_read,
};

#endif /* CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY */

/************** Raw Scheduler task_struct->nvcsw Data Handling ****************/

#ifdef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY

static u32 boot_raw_sched_nvcsw_test = 0;
module_param(boot_raw_sched_nvcsw_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_sched_nvcsw_test, "Enable gathering boot time entropy of the first task context switch numbers collected by the scheduler entropy source");

static struct esdm_testing esdm_raw_sched_nvcsw = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock      = __SPIN_LOCK_UNLOCKED(esdm_raw_sched_nvcsw.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_sched_nvcsw.read_wait)
};

bool esdm_raw_sched_nvcsw_entropy_store(u32 value)
{
	return esdm_testing_store(&esdm_raw_sched_nvcsw, value,
				  &boot_raw_sched_nvcsw_test);
}

static int esdm_raw_sched_nvcsw_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_sched_nvcsw,
				   &boot_raw_sched_nvcsw_test, outbuf, outbuflen);
}

static ssize_t esdm_raw_sched_nvcsw_read(struct file *file, char __user *to,
				       size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_sched_nvcsw_entropy_reader);
}

static const struct file_operations esdm_raw_sched_nvcsw_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_sched_nvcsw_read,
};

#endif /* CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY */

/**************************************************************************
 * Debugfs interface
 **************************************************************************/

int __init esdm_raw_init(struct dentry *esdm_raw_debugfs_root)
{
#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_sched_hires", 0400,
				   esdm_raw_debugfs_root,
				   NULL, &esdm_raw_sched_hires_fops);
#endif
#ifdef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_sched_pid", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_raw_sched_pid_fops);
#endif
#ifdef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_sched_starttime", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_raw_sched_starttime_fops);
#endif
#ifdef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_sched_nvcsw", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_raw_sched_nvcsw_fops);
#endif
#ifdef CONFIG_ESDM_SCHED_PERF
	debugfs_create_file_unsafe("esdm_sched_perf", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_sched_perf_fops);
#endif

	return 0;
}
