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

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vhost_user_mem.h"

/*
 * Offsets into a file are 64 bits on every architecture this is built for -
 * meson defines _FILE_OFFSET_BITS=64 - so a region beyond 2 GiB into its file
 * maps on a 32-bit host as well.
 */
_Static_assert(sizeof(off_t) == 8, "off_t must be 64 bits wide");

/* Whether [a, a + alen) and [b, b + blen) share a byte - neither sum wraps */
static bool vu_mem_overlap(uint64_t a, uint64_t alen, uint64_t b,
			   uint64_t blen)
{
	if (a <= b)
		return b - a < alen;
	return a - b < blen;
}

/*
 * The alignment the offset into the file needs: the page size, or the huge
 * page size of a file on hugetlbfs, which reports it as its block size.
 */
static uint64_t vu_mem_align(const struct stat *sb)
{
	long page = sysconf(_SC_PAGESIZE);
	uint64_t align = page > 0 ? (uint64_t)page : 4096;
	uint64_t blk = sb->st_blksize > 0 ? (uint64_t)sb->st_blksize : 0;

	/* A power of two above the page size, and not absurdly large */
	if (blk > align && !(blk & (blk - 1)) && blk <= (1ULL << 30))
		align = blk;

	return align;
}

int vu_mem_region_map(const struct vhost_user_mem_region *desc, int fd,
		      struct vu_mem_region *r)
{
	uint64_t align, off, delta, len;
	struct stat sb;
	void *map;

	memset(r, 0, sizeof(*r));

	if (fd < 0)
		return -EBADF;

	/*
	 * The last byte of each range has to be addressable: size - 1 rather
	 * than size, so that a region ending at the top of the address space
	 * passes, and no sum below can wrap.
	 */
	if (!desc->memory_size ||
	    desc->memory_size - 1 > UINT64_MAX - desc->guest_phys_addr ||
	    desc->memory_size - 1 > UINT64_MAX - desc->userspace_addr)
		return -EINVAL;

	/* The end of the region within the file has to be an off_t */
	if (desc->mmap_offset > (uint64_t)INT64_MAX ||
	    desc->memory_size > (uint64_t)INT64_MAX - desc->mmap_offset)
		return -EINVAL;

	if (fstat(fd, &sb) < 0)
		return -errno;

	/*
	 * Touching a page of a shared mapping beyond the end of a file raises
	 * SIGBUS. Where the file has a size - a memfd, a file on tmpfs or
	 * hugetlbfs - it has to hold the region. What happens to the file
	 * afterwards is up to the front-end, which owns the memory: shrinking
	 * it under the guest takes down this back-end only.
	 */
	if (S_ISREG(sb.st_mode) &&
	    (sb.st_size < 0 ||
	     (uint64_t)sb.st_size < desc->mmap_offset + desc->memory_size))
		return -EINVAL;

	/*
	 * Map from the offset rounded down to the alignment the file needs,
	 * not from offset 0 as some back-ends do: a region far into a large file
	 * would otherwise take the address space of everything before it, which
	 * on a 32-bit host is the difference between mapping and not.
	 */
	align = vu_mem_align(&sb);
	off = desc->mmap_offset & ~(align - 1);
	delta = desc->mmap_offset - off;
	len = desc->memory_size + delta;
	if (len > UINT64_MAX - (align - 1))
		return -EINVAL;
	len = (len + align - 1) & ~(align - 1);
	if (len > (uint64_t)SIZE_MAX)
		return -ENOMEM;

	map = mmap(NULL, (size_t)len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   (off_t)off);
	if (map == MAP_FAILED)
		return -errno;

	/*
	 * The guest's memory has no business in a core dump of this process.
	 * Best effort: a kernel without MADV_DONTDUMP changes nothing else.
	 */
	(void)madvise(map, (size_t)len, MADV_DONTDUMP);

	r->gpa = desc->guest_phys_addr;
	r->size = desc->memory_size;
	r->uaddr = desc->userspace_addr;
	r->map = map;
	r->map_len = (size_t)len;
	r->host = (uint8_t *)map + (size_t)delta;

	return 0;
}

void vu_mem_region_unmap(struct vu_mem_region *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
	memset(r, 0, sizeof(*r));
}

int vu_mem_add(struct vu_mem *mem, const struct vu_mem_region *r)
{
	unsigned int i;

	if (mem->nregions >= VU_MEM_MAX_REGIONS)
		return -ENOSPC;

	for (i = 0; i < mem->nregions; i++) {
		const struct vu_mem_region *o = &mem->region[i];

		if (vu_mem_overlap(r->gpa, r->size, o->gpa, o->size) ||
		    vu_mem_overlap(r->uaddr, r->size, o->uaddr, o->size))
			return -EEXIST;
	}

	mem->region[mem->nregions++] = *r;

	return 0;
}

int vu_mem_remove(struct vu_mem *mem, uint64_t gpa, uint64_t uaddr,
		  uint64_t size, struct vu_mem_region *removed)
{
	unsigned int i;

	for (i = 0; i < mem->nregions; i++) {
		struct vu_mem_region *r = &mem->region[i];

		if (r->gpa != gpa || r->uaddr != uaddr || r->size != size)
			continue;

		*removed = *r;
		mem->nregions--;
		if (i != mem->nregions)
			memmove(r, r + 1,
				(mem->nregions - i) * sizeof(mem->region[0]));
		memset(&mem->region[mem->nregions], 0, sizeof(mem->region[0]));
		mem->hint = 0;

		return 0;
	}

	return -ENOENT;
}

void vu_mem_clear(struct vu_mem *mem)
{
	unsigned int i;

	for (i = 0; i < mem->nregions; i++)
		vu_mem_region_unmap(&mem->region[i]);
	mem->nregions = 0;
	mem->hint = 0;
}

/*
 * The region holding @addr, as a guest physical address if @guest, as a
 * front-end virtual one otherwise. addr - start < size tells containment
 * without a sum: for an address below the start the difference wraps to more
 * than the region can be long.
 */
static struct vu_mem_region *vu_mem_find(struct vu_mem *mem, uint64_t addr,
					 bool guest)
{
	unsigned int i, n = mem->nregions;
	struct vu_mem_region *r;

	if (mem->hint < n) {
		r = &mem->region[mem->hint];
		if (addr - (guest ? r->gpa : r->uaddr) < r->size)
			return r;
	}

	for (i = 0; i < n; i++) {
		r = &mem->region[i];
		if (addr - (guest ? r->gpa : r->uaddr) < r->size) {
			mem->hint = i;
			return r;
		}
	}

	return NULL;
}

uint8_t *vu_mem_uva(struct vu_mem *mem, uint64_t uaddr, uint64_t len)
{
	struct vu_mem_region *r = vu_mem_find(mem, uaddr, false);
	uint64_t off;

	if (!r)
		return NULL;

	off = uaddr - r->uaddr;
	if (len > r->size - off)
		return NULL;

	return r->host + (size_t)off;
}

uint8_t *vu_mem_gpa(struct vu_mem *mem, uint64_t gpa, uint64_t *avail)
{
	struct vu_mem_region *r = vu_mem_find(mem, gpa, true);
	uint64_t off;

	if (!r)
		return NULL;

	off = gpa - r->gpa;
	*avail = r->size - off;

	return r->host + (size_t)off;
}

bool vu_mem_covers_gpa(struct vu_mem *mem, uint64_t gpa, uint64_t len)
{
	if (!len || len - 1 > UINT64_MAX - gpa)
		return false;

	for (;;) {
		uint64_t avail;

		if (!vu_mem_gpa(mem, gpa, &avail))
			return false;
		if (avail >= len)
			return true;

		/* Not past the end: avail < len, and gpa + len - 1 fits */
		len -= avail;
		gpa += avail;
	}
}

int vu_mem_read_gpa(struct vu_mem *mem, uint64_t gpa, void *dst, size_t len)
{
	uint8_t *d = dst;

	while (len) {
		const volatile uint8_t *s;
		uint64_t avail;
		size_t chunk;

		s = vu_mem_gpa(mem, gpa, &avail);
		if (!s)
			return -EFAULT;

		chunk = avail < len ? (size_t)avail : len;
		len -= chunk;

		/* The rest of the range starts at the next region, if any */
		if (len && (uint64_t)chunk > UINT64_MAX - gpa)
			return -EFAULT;
		gpa += chunk;

		while (chunk--)
			*d++ = *s++;
	}

	return 0;
}
