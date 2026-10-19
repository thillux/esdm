// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend
 *
 * /dev/esdm_random and /dev/esdm_urandom serve the random numbers of the ESDM
 * running in user space with the semantics of the kernel's /dev/random and
 * /dev/urandom, as the CUSE frontend of the ESDM does from user space:
 *
 *  - /dev/esdm_random waits until the ESDM is operational - its DRNG fully
 *    seeded - and then reads from it. O_NONBLOCK gets -EAGAIN instead, and
 *    poll() reports it readable once the ESDM is operational.
 *  - /dev/esdm_urandom reads from the ESDM's DRNG without waiting for it to be
 *    fully seeded.
 *  - Opened with O_SYNC, either reads from the prediction resistance DRNG,
 *    which hands out no more than its entropy sources just delivered. Without
 *    O_NONBLOCK, the read waits for the rest.
 *  - Data written to either is mixed into the ESDM's auxiliary pool without
 *    being credited with entropy.
 *  - The ioctls of the kernel's devices: RNDGETENTCNT for everybody, the ones
 *    changing the entropy accounting only for a caller with CAP_SYS_ADMIN.
 *
 * While the ESDM cannot be reached, reads and writes are served by the
 * kernel's RNG instead, as the CUSE frontend falls back to the kernel's
 * devices: /dev/esdm_random waits for the kernel's RNG to be initialized
 * first. The ioctls fail with -ENOTCONN then, see esdm_cdev_ioctl().
 *
 * The kernel's /dev/random and /dev/urandom are left as they are.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "esdm_cdev.h"

/*
 * What the module knows about the state of the ESDM, see the watcher below.
 * Not authoritative - the reads find out anew - but what the waits and poll()
 * go by.
 */
enum esdm_cdev_esdm_state {
	ESDM_CDEV_UNKNOWN,
	ESDM_CDEV_OPERATIONAL,
	ESDM_CDEV_NOT_OPERATIONAL,
	ESDM_CDEV_UNREACHABLE,
};

static atomic_t esdm_cdev_esdm = ATOMIC_INIT(ESDM_CDEV_UNKNOWN);
static DECLARE_WAIT_QUEUE_HEAD(esdm_cdev_wait);

/* Readers waiting for the ESDM to turn operational */
static atomic_t esdm_cdev_waiters = ATOMIC_INIT(0);
/* A poller waits for it since it was last operational */
static atomic_t esdm_cdev_pollers = ATOMIC_INIT(0);

/* Poll interval of the watcher, and its longest one while unreachable */
#define ESDM_CDEV_WATCH_MS 100
#define ESDM_CDEV_WATCH_MAX_MS 1000

/* Prediction resistant reads ask again after this long for the rest */
#define ESDM_CDEV_PR_RETRY_MS 50

static void esdm_cdev_watch(struct work_struct *work);
static DECLARE_DELAYED_WORK(esdm_cdev_watch_work, esdm_cdev_watch);
static unsigned int esdm_cdev_watch_ms = ESDM_CDEV_WATCH_MS;
static bool esdm_cdev_stopping;

static void esdm_cdev_set_state(enum esdm_cdev_esdm_state state)
{
	if (atomic_xchg(&esdm_cdev_esdm, state) == state)
		return;

	if (state == ESDM_CDEV_OPERATIONAL)
		atomic_set(&esdm_cdev_pollers, 0);
	wake_up_interruptible_all(&esdm_cdev_wait);
}

static void esdm_cdev_watch_kick(void)
{
	if (!READ_ONCE(esdm_cdev_stopping))
		mod_delayed_work(system_unbound_wq, &esdm_cdev_watch_work, 0);
}

/*
 * The watcher: asks the ESDM for its state while somebody waits for it to turn
 * operational, and wakes the waiters once it is - or once it cannot be reached
 * any more, which the waiters then leave to the kernel's RNG.
 *
 * Polling rather than a request that waits in the ESDM: such a request would
 * hold a connection of the pool for as long as the ESDM takes, and the ESDM
 * offers no notification over the EGD socket.
 */
static void esdm_cdev_watch(struct work_struct *work)
{
	struct esdm_cdev_state state;
	int ret;

	ret = esdm_cdev_egd_get_state(&state);
	if (ret) {
		esdm_cdev_set_state(ESDM_CDEV_UNREACHABLE);
		esdm_cdev_watch_ms = min(esdm_cdev_watch_ms * 2,
					 ESDM_CDEV_WATCH_MAX_MS);
	} else {
		esdm_cdev_set_state(state.flags &
						    ESDM_EGD_STATE_FLAG_OPERATIONAL ?
					    ESDM_CDEV_OPERATIONAL :
					    ESDM_CDEV_NOT_OPERATIONAL);
		esdm_cdev_watch_ms = ESDM_CDEV_WATCH_MS;
	}

	if (atomic_read(&esdm_cdev_esdm) == ESDM_CDEV_OPERATIONAL)
		return;

	if ((atomic_read(&esdm_cdev_waiters) ||
	     atomic_read(&esdm_cdev_pollers)) &&
	    !READ_ONCE(esdm_cdev_stopping))
		queue_delayed_work(system_unbound_wq, &esdm_cdev_watch_work,
				   msecs_to_jiffies(esdm_cdev_watch_ms));
}

/*
 * Wait for the ESDM to turn operational after a read found it not. Returns 0
 * when it is worth reading again - operational, or unreachable, for the
 * fallback - or -ERESTARTSYS.
 */
static int esdm_cdev_wait_operational(void)
{
	int ret;

	esdm_cdev_set_state(ESDM_CDEV_NOT_OPERATIONAL);

	atomic_inc(&esdm_cdev_waiters);
	esdm_cdev_watch_kick();
	ret = wait_event_interruptible(esdm_cdev_wait,
				       atomic_read(&esdm_cdev_esdm) !=
					       ESDM_CDEV_NOT_OPERATIONAL);
	atomic_dec(&esdm_cdev_waiters);

	return ret;
}

/********************************* Devices ***********************************/

enum esdm_cdev_type {
	ESDM_CDEV_RANDOM,
	ESDM_CDEV_URANDOM,
};

static struct miscdevice esdm_cdev_random_dev;
static struct miscdevice esdm_cdev_urandom_dev;

static enum esdm_cdev_type esdm_cdev_type(struct file *file)
{
	return file->private_data == &esdm_cdev_urandom_dev ? ESDM_CDEV_URANDOM :
							       ESDM_CDEV_RANDOM;
}

/*
 * The ESDM cannot be reached: serve @len bytes from the kernel's RNG, as the
 * CUSE frontend reads the kernel's devices then. Returns @len, -EAGAIN for a
 * reader that may not wait for the kernel's RNG to be initialized, or
 * -ERESTARTSYS.
 */
static int esdm_cdev_read_fallback(u8 *buf, size_t len, bool seeded,
				   bool nonblock)
{
	if (seeded) {
		if (nonblock && !rng_is_initialized())
			return -EAGAIN;
		if (wait_for_random_bytes())
			return -ERESTARTSYS;
	}

	get_random_bytes(buf, len);

	return (int)len;
}

static ssize_t esdm_cdev_read(struct file *file, char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	bool urandom = esdm_cdev_type(file) == ESDM_CDEV_URANDOM;
	bool nonblock = file->f_flags & O_NONBLOCK;
	bool pr = file->f_flags & O_SYNC;
	/* Waits for the seeding: everything but the plain urandom read */
	bool seeded = !urandom || pr;
	u8 cmd = pr ? ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK :
		      (urandom ? ESDM_EGD_CMD_ESDM_READ_UNSEEDED :
				 ESDM_EGD_CMD_READ_NONBLOCK);
	/*
	 * The prediction resistant reads one command at a time: the ESDM
	 * generates them within a budget per connection and round, see
	 * esdm_egd_protocol.h, a batch would wait for several rounds.
	 */
	size_t max = pr ? ESDM_EGD_MAX_TRANSFER : ESDM_CDEV_READ_MAX;
	size_t done = 0;
	ssize_t ret = 0;
	u8 *block;

	if (!count)
		return 0;

	block = kmalloc(max, GFP_KERNEL);
	if (!block)
		return -ENOMEM;

	while (done < count) {
		size_t len = min_t(size_t, count - done, max);
		int got;

		/* As the kernel's devices, a signal ends the read */
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		cond_resched();

		got = esdm_cdev_egd_read(cmd, block, len);
		if (got == -ERESTARTSYS) {
			ret = got;
			break;
		}

		/*
		 * Nothing from the ESDM but an answer short of all: the
		 * unseeded read is only short on an error.
		 */
		if (urandom && !pr && got >= 0 && (size_t)got < len)
			got = -EIO;

		if (got < 0) {
			pr_debug("ESDM read failed (%d), serving from the kernel RNG\n",
				 got);
			if (seeded)
				esdm_cdev_set_state(ESDM_CDEV_UNREACHABLE);
			got = esdm_cdev_read_fallback(block, len, seeded,
						      nonblock);
			if (got < 0) {
				ret = got;
				break;
			}
		}

		if (!got) {
			/* Not operational, or no prediction resistant data */
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

			if (pr) {
				long tmo = msecs_to_jiffies(ESDM_CDEV_PR_RETRY_MS);

				if (schedule_timeout_interruptible(tmo)) {
					ret = -ERESTARTSYS;
					break;
				}
				continue;
			}

			ret = esdm_cdev_wait_operational();
			if (ret)
				break;
			continue;
		}

		if (!pr)
			esdm_cdev_set_state(ESDM_CDEV_OPERATIONAL);

		if (copy_to_user(ubuf + done, block, got)) {
			ret = -EFAULT;
			break;
		}
		done += got;
	}

	kfree_sensitive(block);

	/* What was read is returned, an error only without any */
	if (done)
		return (ssize_t)done;

	return ret;
}

/*
 * The ESDM cannot be reached: mix the data into the kernel's RNG without
 * crediting it, as a write to the kernel's devices does. Returns what was
 * mixed in, or -EFAULT.
 */
static ssize_t esdm_cdev_write_fallback(const char __user *ubuf, size_t count)
{
	u8 block[ESDM_EGD_MAX_TRANSFER];
	size_t done = 0;

	while (done < count) {
		size_t len = min_t(size_t, count - done, sizeof(block));

		if (copy_from_user(block, ubuf + done, len))
			break;
		add_device_randomness(block, len);
		done += len;

		if (signal_pending(current))
			break;
		cond_resched();
	}

	memzero_explicit(block, sizeof(block));

	return done ? (ssize_t)done : -EFAULT;
}

static ssize_t esdm_cdev_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (!count)
		return 0;

	/* Without entropy credit, as for everybody */
	ret = esdm_cdev_egd_insert_user(ubuf, count);
	if (ret >= 0 || ret == -EFAULT)
		return ret;
	if (ret == -ERESTARTSYS)
		return ret;

	pr_debug("ESDM write failed (%zd), mixing into the kernel RNG\n", ret);

	return esdm_cdev_write_fallback(ubuf, count);
}

/*
 * poll() of /dev/esdm_random, as the kernel's random_poll(): readable once the
 * ESDM is operational, writable before. The kernel's RNG decides while the
 * ESDM cannot be reached, as it serves the reads then.
 */
static __poll_t esdm_cdev_poll(struct file *file, poll_table *wait)
{
	int state;

	poll_wait(file, &esdm_cdev_wait, wait);

	state = atomic_read(&esdm_cdev_esdm);
	if (state == ESDM_CDEV_OPERATIONAL ||
	    (state == ESDM_CDEV_UNREACHABLE && rng_is_initialized()))
		return EPOLLIN | EPOLLRDNORM;

	/* The watcher tells the poller once that changes */
	atomic_set(&esdm_cdev_pollers, 1);
	esdm_cdev_watch_kick();

	return EPOLLOUT | EPOLLWRNORM;
}

/*
 * The ioctls of drivers/char/random.c, with its checks: the caller's
 * capability first, then the arguments.
 *
 * The module is root towards the ESDM, which therefore carries out whatever it
 * sends. That makes the CAP_SYS_ADMIN check here the one that keeps an
 * unprivileged caller from changing the ESDM's entropy accounting.
 *
 * While the ESDM cannot be reached, they fail with -ENOTCONN: the kernel's own
 * entropy accounting cannot be changed from a module, and the kernel's devices
 * are there for that.
 */
static long esdm_cdev_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	int __user *p = (int __user *)arg;
	int ent_count, size, ret;

	switch (cmd) {
	case RNDGETENTCNT: {
		struct esdm_cdev_state state;

		ret = esdm_cdev_egd_get_state(&state);
		if (ret)
			return ret;
		ent_count = (int)min_t(u32, state.ent_cnt, INT_MAX);
		if (put_user(ent_count, p))
			return -EFAULT;
		return 0;
	}
	case RNDADDTOENTCNT:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count, p))
			return -EFAULT;
		if (ent_count < 0)
			return -EINVAL;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT,
					  true, (u32)ent_count);
	case RNDADDENTROPY: {
		ssize_t written;
		u32 bits;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count, p++))
			return -EFAULT;
		if (ent_count < 0)
			return -EINVAL;
		if (get_user(size, p++))
			return -EFAULT;
		if (size < 0)
			return -EINVAL;
		if (!size)
			return 0;

		/*
		 * As random_ioctl(): all of the data first, then the credit,
		 * and none unless all of the data went in. The data goes in
		 * without entropy, into every auxiliary pool of the ESDM, the
		 * credit after it as that of RNDADDTOENTCNT, to the first one.
		 * The insertions themselves cannot carry it: each holds 255
		 * bytes, the claim for all of the data would be given to the
		 * first ones, and kept when a later one failed - a caller
		 * trying again would be credited twice.
		 */
		written = esdm_cdev_egd_insert_user((const char __user *)p,
						    (size_t)size);
		if (written < 0)
			return (long)written;
		/* As the kernel: credited, so it has to be all of it */
		if (written != size)
			return -EFAULT;

		/* No more than the data has bits */
		bits = (u32)min_t(u64, (u64)ent_count, (u64)size * 8);
		if (!bits)
			return 0;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT,
					  true, bits);
	}
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_CLEAR_POOL, false,
					  0);
	case RNDRESEEDCRNG:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_RESEED, false, 0);
	default:
		/* The kernel's random_ioctl() answers with -EINVAL, too */
		return -EINVAL;
	}
}

static const struct file_operations esdm_cdev_random_fops = {
	.owner = THIS_MODULE,
	.read = esdm_cdev_read,
	.write = esdm_cdev_write,
	.poll = esdm_cdev_poll,
	.unlocked_ioctl = esdm_cdev_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

/* As the kernel's urandom_fops: no poll, always readable and writable */
static const struct file_operations esdm_cdev_urandom_fops = {
	.owner = THIS_MODULE,
	.read = esdm_cdev_read,
	.write = esdm_cdev_write,
	.unlocked_ioctl = esdm_cdev_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice esdm_cdev_random_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "esdm_random",
	.fops = &esdm_cdev_random_fops,
	.mode = 0666,
};

static struct miscdevice esdm_cdev_urandom_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "esdm_urandom",
	.fops = &esdm_cdev_urandom_fops,
	.mode = 0666,
};

/********************************** Module ***********************************/

static void esdm_cdev_watch_stop(void)
{
	WRITE_ONCE(esdm_cdev_stopping, true);
	cancel_delayed_work_sync(&esdm_cdev_watch_work);
}

static int __init esdm_cdev_init(void)
{
	int ret;

	ret = esdm_cdev_egd_init();
	if (ret)
		return ret;

	ret = esdm_cdev_proc_init();
	if (ret)
		goto err_egd;

	ret = misc_register(&esdm_cdev_random_dev);
	if (ret)
		goto err_proc;

	ret = misc_register(&esdm_cdev_urandom_dev);
	if (ret)
		goto err_random;

	/* Learn the state of the ESDM, without waiting for it */
	esdm_cdev_watch_kick();

	return 0;

err_random:
	misc_deregister(&esdm_cdev_random_dev);
err_proc:
	esdm_cdev_proc_fini();
err_egd:
	esdm_cdev_watch_stop();
	esdm_cdev_egd_fini();
	return ret;
}

/*
 * The devices hold a reference to the module while they are open, so nobody
 * reads or waits in them once this runs. The proc files are removed waiting
 * for the ones being read, and the watcher is stopped before the connections
 * it uses go away.
 */
static void __exit esdm_cdev_exit(void)
{
	misc_deregister(&esdm_cdev_urandom_dev);
	misc_deregister(&esdm_cdev_random_dev);
	esdm_cdev_proc_fini();
	esdm_cdev_watch_stop();
	esdm_cdev_egd_fini();
}

module_init(esdm_cdev_init);
module_exit(esdm_cdev_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Markus Theil <theil.markus@gmail.com>");
MODULE_DESCRIPTION("ESDM character device frontend");
