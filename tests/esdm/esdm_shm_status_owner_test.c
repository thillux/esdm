/*
 * The status segment has a well-known key, so another local user can create it
 * before the server does. The server removes such a segment and creates its
 * own - but removing it frees the key for everybody: a user that creates the
 * segment in a loop gets it back in the window before the server's creation.
 * This test plays that user from a child running as uid 1 and checks that the
 * server never publishes into a segment it did not create - it may fail to
 * set one up while the other user keeps winning, which is all it can do.
 *
 * The test needs root for the second uid (a mapped root with uid 1 mapped
 * does) and is skipped otherwise.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm_config.h"
#include "esdm_logger.h"
#include "esdm_rpc_service.h"
#include "esdm_shm_status.h"

#define OTHER_UID 1
#define RACE_ROUNDS 500

/* Become the other user, or report that this is not possible */
static int become_other_user(void)
{
	if (setgid(OTHER_UID) || setuid(OTHER_UID))
		return 1;
	return 0;
}

/*
 * The identifier of the status segment attached by this process: an attached
 * System V segment shows in the maps as /SYSV<key>, with the identifier as its
 * inode number.
 */
static int attached_shmid(key_t key)
{
	char line[512], name[32];
	FILE *maps = fopen("/proc/self/maps", "r");
	int shmid = -1;

	if (!maps)
		return -1;

	snprintf(name, sizeof(name), "/SYSV%08x", (unsigned int)key);
	while (fgets(line, sizeof(line), maps)) {
		unsigned long inode;

		if (!strstr(line, name))
			continue;
		if (sscanf(line, "%*s %*s %*s %*s %lu", &inode) == 1)
			shmid = (int)inode;
		break;
	}

	fclose(maps);

	return shmid;
}

/* 0 when the attached segment is ours, 1 when not or when there is none */
static int check_attached_owner(key_t key, const char *what)
{
	struct shmid_ds buf;
	int shmid = attached_shmid(key);

	if (shmid < 0) {
		printf("%s: no status segment attached\n", what);
		return 1;
	}

	if (shmctl(shmid, IPC_STAT, &buf)) {
		printf("%s: status segment %d cannot be inspected: %s\n", what,
		       shmid, strerror(errno));
		return 1;
	}

	if (buf.shm_perm.cuid != geteuid()) {
		printf("%s: status segment %d was created by uid %u\n", what,
		       shmid, (unsigned int)buf.shm_perm.cuid);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	unsigned int i, published = 0, refused = 0;
	pid_t pid;
	int ret = 1, status;

	(void)argc;
	(void)argv;

	if (geteuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	esdm_logger_set_verbosity(LOGGER_WARN);

	/* The other user's segment is removed again on every exit */
	esdm_config_ipc_cleanup_set(1);

	/* A segment planted before the server starts is replaced */
	pid = fork();
	if (pid < 0)
		return 1;
	if (!pid) {
		if (become_other_user())
			_exit(77);
		_exit(shmget(key, sizeof(struct esdm_shm_status),
			     IPC_CREAT | IPC_EXCL | 0666) < 0);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return 1;
	if (WEXITSTATUS(status) == 77) {
		printf("Cannot become uid %u\n", OTHER_UID);
		return 77;
	}
	if (WEXITSTATUS(status)) {
		printf("Other user could not plant the status segment\n");
		return 1;
	}

	if (esdm_shm_status_init()) {
		printf("Status segment not set up over a planted one\n");
		return 1;
	}
	if (check_attached_owner(key, "planted segment"))
		goto out;
	esdm_shm_status_exit();

	/* The other user keeps creating the segment while the server starts */
	pid = fork();
	if (pid < 0)
		return 1;
	if (!pid) {
		if (become_other_user())
			_exit(77);
		for (;;)
			shmget(key, sizeof(struct esdm_shm_status),
			       IPC_CREAT | 0666);
	}

	for (i = 0; i < RACE_ROUNDS; i++) {
		if (esdm_shm_status_init()) {
			refused++;
			continue;
		}

		published++;
		if (check_attached_owner(key, "racing segment")) {
			esdm_shm_status_exit();
			goto kill;
		}
		esdm_shm_status_exit();
	}

	printf("Status segment set up %u times, refused %u times, never in another user's segment\n",
	       published, refused);
	ret = 0;

kill:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return ret;

out:
	esdm_shm_status_exit();
	return ret;
}
