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
 * The guest memory a vhost-user front-end shares with the back-end: regions of
 * file descriptors mapped into this process, and the translation of the two
 * kinds of addresses that point into them - guest physical addresses, which
 * the descriptors of the guest carry, and the front-end's own virtual
 * addresses, which it gives the rings by.
 *
 * Every address comes from the outside, and none is trusted: a translation
 * either yields memory that lies within a mapped region in its entirety or
 * fails, and is computed so that no sum can wrap around.
 */

#ifndef VHOST_USER_MEM_H
#define VHOST_USER_MEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vhost_user.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory regions the back-end maps at most, the value of GET_MAX_MEM_SLOTS.
 * The limit of libvhost-user and of the rust-vmm back-ends: the 512 slots of
 * KVM minus those QEMU needs for itself, so a back-end never is the reason a
 * guest cannot get more memory plugged in.
 */
#define VU_MEM_MAX_REGIONS 509

struct vu_mem_region {
	/* Guest physical address of the first byte */
	uint64_t gpa;
	/* Length, at least 1, and gpa + size - 1 and uaddr + size - 1 do not wrap */
	uint64_t size;
	/* Front-end virtual address of the first byte */
	uint64_t uaddr;
	/* Where the first byte is mapped in this process */
	uint8_t *host;
	/* The mapping holding it, for munmap(2) */
	void *map;
	size_t map_len;
};

struct vu_mem {
	unsigned int nregions;
	/* The region the last translation hit - most of them hit it again */
	unsigned int hint;
	struct vu_mem_region region[VU_MEM_MAX_REGIONS];
};

/**
 * @brief Map a region the front-end describes
 *
 * The region is checked for arithmetic sanity - a size of at least 1, a range
 * of guest and front-end addresses that does not wrap, an offset into the file
 * that fits - and, where the file is a regular one, for lying within the file:
 * memory beyond its end would raise SIGBUS rather than be read. The mapping is
 * excluded from core dumps, as it is the memory of the guest.
 *
 * @param [in] desc The region as the message describes it
 * @param [in] fd Descriptor of the memory, not consumed
 * @param [out] r The mapped region
 *
 * @return 0 on success, < 0 on error
 */
int vu_mem_region_map(const struct vhost_user_mem_region *desc, int fd,
		      struct vu_mem_region *r);

/** @brief Unmap a region mapped with vu_mem_region_map(), if it is */
void vu_mem_region_unmap(struct vu_mem_region *r);

/**
 * @brief Add a mapped region to a table
 *
 * A region overlapping one of the table, in guest or in front-end addresses,
 * is refused: the vhost-user specification forbids it, and translations rely
 * on every address naming one location at most.
 *
 * @return 0 when the table took over the region, -EEXIST for an overlap,
 *	   -ENOSPC when the table is full; the region stays the caller's then
 */
int vu_mem_add(struct vu_mem *mem, const struct vu_mem_region *r);

/**
 * @brief Take the region of the given addresses and size out of a table
 *
 * @param [out] removed The region taken out, for the caller to unmap once
 *		       nothing uses it any more
 *
 * @return 0 on success, -ENOENT if the table holds no such region
 */
int vu_mem_remove(struct vu_mem *mem, uint64_t gpa, uint64_t uaddr,
		  uint64_t size, struct vu_mem_region *removed);

/** @brief Unmap every region of a table and empty it */
void vu_mem_clear(struct vu_mem *mem);

/**
 * @brief Translate a range of front-end virtual addresses
 *
 * @return the mapped address of @uaddr if [uaddr, uaddr + len) lies within one
 *	   region, NULL otherwise
 */
uint8_t *vu_mem_uva(struct vu_mem *mem, uint64_t uaddr, uint64_t len);

/**
 * @brief Translate a guest physical address
 *
 * @param [out] avail Bytes mapped contiguously from @gpa on, at least 1
 *
 * @return the mapped address of @gpa, NULL if no region holds it
 */
uint8_t *vu_mem_gpa(struct vu_mem *mem, uint64_t gpa, uint64_t *avail);

/**
 * @brief Whether [gpa, gpa + len) is guest memory in its entirety
 *
 * The range may span adjacent regions, and has to be at least one byte long
 * without wrapping around.
 */
bool vu_mem_covers_gpa(struct vu_mem *mem, uint64_t gpa, uint64_t len);

/**
 * @brief Copy guest memory out by guest physical address
 *
 * The range may span adjacent regions. Every byte is read exactly once and
 * with a volatile access, so what the caller looks at is the copy, and the
 * guest changing the memory meanwhile changes nothing the caller sees.
 *
 * @return 0 on success, -EFAULT if a part of the range is not mapped
 */
int vu_mem_read_gpa(struct vu_mem *mem, uint64_t gpa, void *dst, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VHOST_USER_MEM_H */
