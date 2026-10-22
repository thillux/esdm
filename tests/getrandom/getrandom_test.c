/* getrandom system call tester
 *
 * Copyright (C) 2021 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/syscall.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "getrandom.h"

/******************************************************************************/

static char hex_char(unsigned int bin, int u)
{
	static const char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5',
					       '6', '7', '8', '9', 'a', 'b',
					       'c', 'd', 'e', 'f' };
	static const char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5',
					       '6', '7', '8', '9', 'A', 'B',
					       'C', 'D', 'E', 'F' };
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/**
 * Convert binary string into hex representation
 * @bin [in] input buffer with binary data
 * @binlen [in] length of bin
 * @hex [out] output buffer to store hex data
 * @hexlen [in] length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u [in] case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const uint8_t *bin, uint32_t binlen, char *hex,
		    uint32_t hexlen, int u)
{
	uint32_t i;
	uint32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i * 2)] = hex_char((bin[i] >> 4), u);
		hex[((i * 2) + 1)] = hex_char((bin[i] & 0x0f), u);
	}
}

/*
 * Take the kernel out of the picture: from here on, the getrandom system call
 * of this process fails with ENOSYS. The library falls back to it whenever the
 * ESDM does not answer, so random bytes that still arrive came from the ESDM -
 * and a fallback shows up as a failed call instead of passing unnoticed.
 *
 * The server was started before and is not affected. The filter does not look
 * at the architecture of the call: all it can get wrong is to fail a system
 * call of a foreign ABI that has the same number, and this test makes none.
 */
static int deny_kernel_getrandom(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0))
		return -errno;

	return 0;
}

static int check_getrandom(const char *call, ssize_t rc, const uint8_t *random,
			   size_t len)
{
	char hex_random[2 * 16 + 1];

	if (rc < 0) {
		printf("%s call failed - the ESDM did not answer it: %s\n",
		       call, strerror(errno));
		return 1;
	}
	if ((size_t)rc != len) {
		printf("%s returned %zd bytes, expected %zu\n", call, rc, len);
		return 1;
	}

	hex_random[sizeof(hex_random) - 1] = '\0';
	bin2hex(random, (uint32_t)len, hex_random, sizeof(hex_random) - 1, 0);
	printf("%s: random value %s\n", call, hex_random);

	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t random[16];
	ssize_t rc;
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	ret = deny_kernel_getrandom();
	if (ret) {
		printf("Cannot keep the kernel from answering getrandom: %s\n",
		       strerror(-ret));
		ret = 1;
		goto out;
	}

	/* The filter is in place: the kernel's own call is refused */
	rc = syscall(__NR_getrandom, random, sizeof(random), 0);
	if (rc >= 0 || errno != ENOSYS) {
		printf("the kernel still answers getrandom: %zd\n", rc);
		ret = 1;
		goto out;
	}

	rc = getrandom_random(random, sizeof(random));
	ret |= check_getrandom("getrandom(GRND_RANDOM)", rc, random,
			       sizeof(random));

	rc = getrandom_urandom(random, sizeof(random));
	ret |= check_getrandom("getrandom(0)", rc, random, sizeof(random));

out:
	env_fini();

	return ret;
}
