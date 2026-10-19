/*
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

/*
 * An example external entropy source plugin - see libesdm_es_ext(3).
 *
 * It reads a character device delivering noise, /dev/hwrng unless
 * ESDM_ES_EXT_EXAMPLE_DEVICE names another one at build time, and claims one
 * bit of entropy per byte read - the entropy rate it declares as well, 32 bits
 * per 256 bits of data. A real plugin claims and declares what the assessment
 * of its noise source supports. The ESDM shows it under its name, and its
 * status, which names the device and counts the reads.
 *
 * Build it as a shared library:
 *
 *	cc -shared -fPIC -fvisibility=hidden -o esdm_es_ext_example.so \
 *		esdm_es_ext_example.c $(pkg-config --cflags esdm_es_ext)
 *
 * and load it into the ESDM, or serve it from a process of its own:
 *
 *	esdm-server --es_ext_lib ./esdm_es_ext_example.so
 *	esdm-es-ext-serve --plugin ./esdm_es_ext_example.so \
 *		--socket /run/esdm-es-ext-example.socket
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Where the ESDM installs it, as a plugin built on its own includes it */
#include <esdm/esdm_es_ext.h>

#ifndef ESDM_ES_EXT_EXAMPLE_DEVICE
#define ESDM_ES_EXT_EXAMPLE_DEVICE "/dev/hwrng"
#endif

struct example_ctx {
	int fd;
	unsigned long reads;
	unsigned long failures;
};

/*
 * Runs while the ESDM still has its privileges: the device is opened here, as
 * the daemon may not be able to open it later.
 */
static int example_init(void **ctx)
{
	struct example_ctx *c = malloc(sizeof(*c));

	if (!c)
		return -ENOMEM;

	c->reads = 0;
	c->failures = 0;
	c->fd = open(ESDM_ES_EXT_EXAMPLE_DEVICE, O_RDONLY | O_CLOEXEC);
	if (c->fd < 0) {
		int ret = -errno;

		free(c);
		return ret;
	}

	*ctx = c;
	return 0;
}

static void example_fini(void *ctx)
{
	struct example_ctx *c = ctx;

	close(c->fd);
	free(c);
}

static int example_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
			       uint32_t *entropy_bits)
{
	struct example_ctx *c = ctx;
	size_t done = 0;

	/* All of the buffer, or a failure: a short block is no block */
	while (done < buflen) {
		ssize_t ret = read(c->fd, buf + done, buflen - done);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0) {
			c->failures++;
			return ret < 0 ? -errno : -EIO;
		}
		done += (size_t)ret;
	}

	c->reads++;
	*entropy_bits = (uint32_t)buflen;
	return 0;
}

/* Nothing to test without consuming data - the device is still open */
static int example_selftest(void *ctx)
{
	struct example_ctx *c = ctx;

	return fcntl(c->fd, F_GETFD) < 0 ? -EBADF : 0;
}

/*
 * The entropy rate of the source, bits per 256 bits of data, asked for once
 * after the init: the ESDM credits a block at most at this rate, unless a rate
 * is configured for the source there. A plugin may decide it from what its
 * init found - one bit per byte here, as the claims of example_get_entropy().
 */
static uint32_t example_entropy_rate(void *ctx)
{
	(void)ctx;
	return 32;
}

/*
 * One JSON object. The device name is a constant of the build without
 * anything JSON would have to escape.
 */
static int example_status_json(void *ctx, char *buf, size_t buflen)
{
	struct example_ctx *c = ctx;
	int len = snprintf(buf, buflen,
			   "{\"device\":\"%s\",\"reads\":%lu,\"failures\":%lu}",
			   ESDM_ES_EXT_EXAMPLE_DEVICE, c->reads, c->failures);

	if (len < 0)
		return -EIO;
	return (size_t)len < buflen ? 0 : -EMSGSIZE;
}

ESDM_ES_EXT_PLUGIN_EXPORT
const struct esdm_es_ext_plugin esdm_es_ext_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = "example (" ESDM_ES_EXT_EXAMPLE_DEVICE ")",
	.init = example_init,
	.fini = example_fini,
	.get_entropy = example_get_entropy,
	.selftest = example_selftest,
	.status_json = example_status_json,
	.entropy_rate = example_entropy_rate,
};
