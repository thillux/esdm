/*
 * Test: the client library leaves the stacks of other threads alone
 *
 * glibc reserves the TLS of a library loaded at program start in every
 * thread's stack. With 129 KiB of __thread buffers in the client, creating a
 * thread with a 64 KiB stack failed with EINVAL in any process linking the
 * library, before it ever called into it.
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

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "esdm_rpc_client.h"

#define TEST_STACK_SIZE (64 * 1024)

static void *thread_fn(void *arg)
{
	/* Use some of the stack, as a thread of that size may */
	volatile char scratch[TEST_STACK_SIZE / 4];

	memset((char *)scratch, 0x5a, sizeof(scratch));
	*(int *)arg = scratch[0];

	return NULL;
}

int main(void)
{
	pthread_attr_t attr;
	pthread_t thread;
	int ret, val = 0;

	/* Keep the library linked in */
	if (esdm_rpcc_set_max_online_nodes(1)) {
		fprintf(stderr, "esdm_rpcc_set_max_online_nodes failed\n");
		return 1;
	}

	if (pthread_attr_init(&attr) ||
	    pthread_attr_setstacksize(&attr, TEST_STACK_SIZE)) {
		fprintf(stderr, "Cannot set up the thread attributes\n");
		return 1;
	}

	ret = pthread_create(&thread, &attr, thread_fn, &val);
	pthread_attr_destroy(&attr);
	if (ret) {
		fprintf(stderr, "Thread with %d bytes of stack: %s\n",
			TEST_STACK_SIZE, strerror(ret));
		return 1;
	}
	pthread_join(thread, NULL);

	return val == 0x5a ? 0 : 1;
}
