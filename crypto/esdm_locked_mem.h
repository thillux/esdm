/* Locked memory for the DRNG states
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

#ifndef ESDM_LOCKED_MEM_H
#define ESDM_LOCKED_MEM_H

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory for DRNG states which is kept out of swap space.
 *
 * mlock()/munlock() work on whole pages and do not nest: one munlock()
 * unlocks a page no matter how many allocations sharing it locked it. The
 * allocation therefore owns its pages - page aligned and rounded up to whole
 * pages - so releasing one state never unlocks the memory of another.
 */
static inline size_t esdm_locked_mem_size(size_t size)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	size_t ps = (pagesize > 0) ? (size_t)pagesize : 4096;

	return (size + ps - 1) & ~(ps - 1);
}

/*
 * Allocate @size bytes of locked memory. Without the privilege (EPERM) or
 * the RLIMIT_MEMLOCK budget (ENOMEM, EAGAIN) to lock memory, carry on with
 * the memory unlocked.
 *
 * @return 0 upon success; < 0 on error
 */
static inline int esdm_locked_mem_alloc(void **mem, size_t size)
{
	size_t len = esdm_locked_mem_size(size);
	void *tmp = NULL;
	int ret = posix_memalign(&tmp, esdm_locked_mem_size(1), len);

	*mem = NULL;
	if (ret)
		return -ret;

	ret = mlock(tmp, len);
	if (ret && errno != EPERM && errno != EAGAIN && errno != ENOMEM) {
		/* A failure must never read as success with *mem left NULL */
		int errsv = errno ? errno : ENOMEM;

		free(tmp);
		return -errsv;
	}

	*mem = tmp;

	return 0;
}

/* Release memory of @size bytes from esdm_locked_mem_alloc() */
static inline void esdm_locked_mem_free(void *mem, size_t size)
{
	if (!mem)
		return;

	munlock(mem, esdm_locked_mem_size(size));
	free(mem);
}

#ifdef __cplusplus
}
#endif

#endif /* ESDM_LOCKED_MEM_H */
