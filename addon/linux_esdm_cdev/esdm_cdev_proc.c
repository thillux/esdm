// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend - /proc/esdm
 *
 * The files of the kernel's /proc/sys/kernel/random, served by the ESDM, as
 * the CUSE frontend's esdm-proc emulates them, plus the status of the ESDM:
 *
 *  boot_id			the kernel's boot_id, read once at load time
 *  uuid			a fresh random UUID per read
 *  entropy_avail		entropy of the ESDM's auxiliary pool in bits
 *  poolsize			size of that pool in bits
 *  write_wakeup_threshold	writable with CAP_SYS_ADMIN
 *  urandom_min_reseed_secs	writable with CAP_SYS_ADMIN
 *  esdm_type			the status report of the ESDM, as esdm-proc
 *  status			the status report of the ESDM
 *  status.json			the status of the ESDM as JSON document
 *
 * A file is filled when it is opened, so that one open reads one consistent
 * snapshot, also in several reads and after seeking. While the ESDM cannot be
 * reached, the files it fills are empty, as with esdm-proc.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uuid.h>

#include "esdm_cdev.h"

/* Length of a UUID in text with its newline */
#define ESDM_CDEV_UUID_LEN 37

struct esdm_cdev_proc_file {
	const char *name;
	umode_t mode;
	/* Fill the snapshot, kvmalloc()ed, in *text of *len bytes */
	int (*fill)(const struct esdm_cdev_proc_file *file, char **text,
		    size_t *len);
	/* The command setting the value of a writable file */
	u8 set_cmd;
	/* Offset of the value in struct esdm_cdev_state */
	size_t state_off;
	/* Status: as JSON document? */
	bool json;
};

/* The kernel's boot_id with its newline, empty if it could not be read */
static char esdm_cdev_boot_id[ESDM_CDEV_UUID_LEN + 1];

static struct proc_dir_entry *esdm_cdev_proc_dir;

static int esdm_cdev_text(char **text, size_t *len, const char *str,
			  size_t slen)
{
	*text = kvmalloc(slen + 1, GFP_KERNEL);
	if (!*text)
		return -ENOMEM;

	memcpy(*text, str, slen);
	(*text)[slen] = '\0';
	*len = slen;

	return 0;
}

static int esdm_cdev_fill_boot_id(const struct esdm_cdev_proc_file *file,
				  char **text, size_t *len)
{
	return esdm_cdev_text(text, len, esdm_cdev_boot_id,
			      strlen(esdm_cdev_boot_id));
}

static int esdm_cdev_fill_uuid(const struct esdm_cdev_proc_file *file,
			       char **text, size_t *len)
{
	char str[ESDM_CDEV_UUID_LEN + 1];
	u8 uuid[16];
	int ret;

	/*
	 * As the kernel's uuid file, which uses get_random_bytes(): a UUID is
	 * not a key, so the DRNG need not be fully seeded for it.
	 */
	ret = esdm_cdev_egd_read(ESDM_EGD_CMD_ESDM_READ_UNSEEDED, uuid,
				 sizeof(uuid));
	if (ret == -ERESTARTSYS)
		return ret;
	if (ret != sizeof(uuid)) {
		memzero_explicit(uuid, sizeof(uuid));
		return esdm_cdev_text(text, len, "", 0);
	}

	/* Version 4, variant 1: a random UUID */
	uuid[6] = (uuid[6] & 0x0f) | 0x40;
	uuid[8] = (uuid[8] & 0x3f) | 0x80;

	snprintf(str, sizeof(str), "%pUb\n", uuid);
	memzero_explicit(uuid, sizeof(uuid));

	ret = esdm_cdev_text(text, len, str, strlen(str));
	memzero_explicit(str, sizeof(str));

	return ret;
}

static int esdm_cdev_fill_state(const struct esdm_cdev_proc_file *file,
				char **text, size_t *len)
{
	struct esdm_cdev_state state;
	char str[16];
	int ret;

	ret = esdm_cdev_egd_get_state(&state);
	if (ret == -ERESTARTSYS)
		return ret;
	if (ret)
		return esdm_cdev_text(text, len, "", 0);

	snprintf(str, sizeof(str), "%u\n",
		 *(u32 *)((u8 *)&state + file->state_off));

	return esdm_cdev_text(text, len, str, strlen(str));
}

static int esdm_cdev_fill_status(const struct esdm_cdev_proc_file *file,
				 char **text, size_t *len)
{
	int ret = esdm_cdev_egd_status(file->json, text, len);

	if (ret == -ERESTARTSYS)
		return ret;
	if (ret)
		return esdm_cdev_text(text, len, "", 0);

	return 0;
}

static const struct esdm_cdev_proc_file esdm_cdev_proc_files[] = {
	{
		.name = "boot_id",
		.mode = 0444,
		.fill = esdm_cdev_fill_boot_id,
	},
	{
		.name = "uuid",
		.mode = 0444,
		.fill = esdm_cdev_fill_uuid,
	},
	{
		.name = "entropy_avail",
		.mode = 0444,
		.fill = esdm_cdev_fill_state,
		.state_off = offsetof(struct esdm_cdev_state, ent_cnt),
	},
	{
		.name = "poolsize",
		.mode = 0444,
		.fill = esdm_cdev_fill_state,
		.state_off = offsetof(struct esdm_cdev_state, poolsize),
	},
	{
		.name = "write_wakeup_threshold",
		.mode = 0644,
		.fill = esdm_cdev_fill_state,
		.set_cmd = ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP,
		.state_off = offsetof(struct esdm_cdev_state, write_wakeup),
	},
	{
		.name = "urandom_min_reseed_secs",
		.mode = 0644,
		.fill = esdm_cdev_fill_state,
		.set_cmd = ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
		.state_off = offsetof(struct esdm_cdev_state, min_reseed_secs),
	},
	{
		.name = "esdm_type",
		.mode = 0444,
		.fill = esdm_cdev_fill_status,
	},
	{
		.name = "status",
		.mode = 0444,
		.fill = esdm_cdev_fill_status,
	},
	{
		.name = "status.json",
		.mode = 0444,
		.fill = esdm_cdev_fill_status,
		.json = true,
	},
};

/* The snapshot of an open file */
struct esdm_cdev_proc_snap {
	char *text;
	size_t len;
};

static int esdm_cdev_proc_show(struct seq_file *m, void *v)
{
	struct esdm_cdev_proc_snap *snap = m->private;

	seq_write(m, snap->text, snap->len);

	return 0;
}

static int esdm_cdev_proc_open(struct inode *inode, struct file *filp)
{
	const struct esdm_cdev_proc_file *file = pde_data(inode);
	struct esdm_cdev_proc_snap *snap;
	int ret;

	snap = kzalloc(sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	ret = file->fill(file, &snap->text, &snap->len);
	if (ret)
		goto err;

	/* The seq_file buffer fits the snapshot from the start */
	ret = single_open_size(filp, esdm_cdev_proc_show, snap, snap->len + 1);
	if (ret)
		goto err;

	return 0;

err:
	if (snap->text)
		kvfree_sensitive(snap->text, snap->len);
	kfree(snap);
	return ret;
}

static int esdm_cdev_proc_release(struct inode *inode, struct file *filp)
{
	struct seq_file *m = filp->private_data;
	struct esdm_cdev_proc_snap *snap = m->private;

	kvfree_sensitive(snap->text, snap->len);
	kfree(snap);

	return single_release(inode, filp);
}

/*
 * Set the value of write_wakeup_threshold or urandom_min_reseed_secs. The
 * kernel's files are root's to write; here the ESDM carries out what the
 * module sends as root, so the writer needs CAP_SYS_ADMIN, as for the
 * privileged ioctls. The value is parsed like the kernel's proc_dointvec():
 * a number, with a newline after it.
 */
static ssize_t esdm_cdev_proc_write(struct file *filp, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	const struct esdm_cdev_proc_file *file = pde_data(file_inode(filp));
	u32 val;
	int ret;

	if (!file->set_cmd)
		return -EIO;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtou32_from_user(ubuf, count, 0, &val);
	if (ret)
		return ret;
	/* The value has to fit the 32 bit interface, as for esdm-proc */
	if (val == U32_MAX)
		return -ERANGE;

	ret = esdm_cdev_egd_priv(file->set_cmd, true, val);
	if (ret)
		return ret;

	return (ssize_t)count;
}

static const struct proc_ops esdm_cdev_proc_ops = {
	.proc_open = esdm_cdev_proc_open,
	.proc_read = seq_read,
	.proc_write = esdm_cdev_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = esdm_cdev_proc_release,
};

/* Runs on the workqueue: the kernel's boot_id, of the initial namespaces */
static int esdm_cdev_read_boot_id(void *out)
{
	struct file *filp;
	loff_t pos = 0;
	ssize_t ret;

	filp = filp_open("/proc/sys/kernel/random/boot_id", O_RDONLY, 0);
	if (IS_ERR(filp))
		return (int)PTR_ERR(filp);

	ret = kernel_read(filp, out, ESDM_CDEV_UUID_LEN, &pos);
	filp_close(filp, NULL);

	if (ret != ESDM_CDEV_UUID_LEN)
		return ret < 0 ? (int)ret : -EIO;

	return 0;
}

int esdm_cdev_proc_init(void)
{
	char boot_id[ESDM_CDEV_UUID_LEN];
	unsigned int i;
	int ret;

	ret = esdm_cdev_run_in_init(esdm_cdev_read_boot_id, NULL, boot_id,
				    sizeof(boot_id), 5000);
	if (!ret && boot_id[ESDM_CDEV_UUID_LEN - 1] == '\n') {
		memcpy(esdm_cdev_boot_id, boot_id, sizeof(boot_id));
		esdm_cdev_boot_id[ESDM_CDEV_UUID_LEN] = '\0';
	} else {
		pr_warn("cannot read the kernel's boot_id: %d\n", ret);
	}

	esdm_cdev_proc_dir = proc_mkdir("esdm", NULL);
	if (!esdm_cdev_proc_dir)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(esdm_cdev_proc_files); i++) {
		const struct esdm_cdev_proc_file *file =
			&esdm_cdev_proc_files[i];

		if (!proc_create_data(file->name, file->mode,
				      esdm_cdev_proc_dir, &esdm_cdev_proc_ops,
				      (void *)file)) {
			proc_remove(esdm_cdev_proc_dir);
			esdm_cdev_proc_dir = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

/* Waits for the files being opened, read or written */
void esdm_cdev_proc_fini(void)
{
	proc_remove(esdm_cdev_proc_dir);
	esdm_cdev_proc_dir = NULL;
}
