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
 * The guest memory table of esdm-vhost-user-rng on its own: what a region may
 * be, and the translation of addresses at the edges of the regions and of
 * the address space, where a sum would wrap around if it were computed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../test_plan.h"
#include "vhost_user_mem.h"

static unsigned int test_failures;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!TEST_CHECK(cond, __VA_ARGS__))                            \
			test_failures++;                                       \
	} while (0)

#define TEST_SIZE (64 * 1024)

static int test_memfd(size_t size)
{
	int fd = memfd_create("esdm-vu-mem-test", MFD_CLOEXEC);

	if (fd >= 0 && ftruncate(fd, (off_t)size) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void test_region_checks(int fd)
{
	struct vhost_user_mem_region d = { .guest_phys_addr = 0x1000,
					   .memory_size = TEST_SIZE,
					   .userspace_addr = 0x7f0000000000ULL,
					   .mmap_offset = 0 };
	struct vu_mem_region r;
	uint8_t *view;
	int ret;

	TEST_STEP("regions the back-end refuses");

	d.memory_size = 0;
	CHECK(vu_mem_region_map(&d, fd, &r) == -EINVAL, "size 0 refused");

	d.memory_size = TEST_SIZE;
	d.guest_phys_addr = UINT64_MAX - TEST_SIZE + 2;
	CHECK(vu_mem_region_map(&d, fd, &r) == -EINVAL,
	      "guest range wrapping around refused");

	d.guest_phys_addr = 0x1000;
	d.userspace_addr = UINT64_MAX - 10;
	CHECK(vu_mem_region_map(&d, fd, &r) == -EINVAL,
	      "front-end range wrapping around refused");

	d.userspace_addr = 0x7f0000000000ULL;
	d.mmap_offset = 4096;
	CHECK(vu_mem_region_map(&d, fd, &r) == -EINVAL,
	      "region beyond the end of the file refused");

	d.mmap_offset = UINT64_MAX - 100;
	CHECK(vu_mem_region_map(&d, fd, &r) == -EINVAL,
	      "offset beyond off_t refused");

	d.mmap_offset = 0;
	CHECK(vu_mem_region_map(&d, -1, &r) == -EBADF, "no descriptor refused");

	TEST_STEP("a region ending at the top of the guest address space");
	d.guest_phys_addr = UINT64_MAX - TEST_SIZE + 1;
	ret = vu_mem_region_map(&d, fd, &r);
	CHECK(!ret, "mapped: %d", ret);
	if (!ret)
		vu_mem_region_unmap(&r);

	TEST_STEP("a region at an offset into its file that is not page aligned");
	d.guest_phys_addr = 0x1000;
	d.mmap_offset = 0x10;
	d.memory_size = TEST_SIZE - 0x10;
	ret = vu_mem_region_map(&d, fd, &r);
	CHECK(!ret, "mapped: %d", ret);
	if (ret)
		return;

	view = mmap(NULL, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(view != MAP_FAILED, "file mapped by the test");
	if (view != MAP_FAILED) {
		view[0x10] = 0xa5;
		view[TEST_SIZE - 1] = 0x5a;
		CHECK(r.host[0] == 0xa5 && r.host[TEST_SIZE - 0x11] == 0x5a,
		      "the region starts at the offset into the file");
		munmap(view, TEST_SIZE);
	}
	vu_mem_region_unmap(&r);
}

static void test_translation(int fd1, int fd2)
{
	struct vhost_user_mem_region d = { .memory_size = TEST_SIZE };
	struct vu_mem *mem = calloc(1, sizeof(*mem));
	struct vu_mem_region r, removed;
	uint8_t buf[64];
	uint64_t avail;
	uint8_t *p;
	unsigned int i;
	int ret;

	if (!mem) {
		test_failures++;
		return;
	}

	TEST_STEP("two adjacent regions");
	d.guest_phys_addr = 0x100000;
	d.userspace_addr = 0x7f0000000000ULL;
	ret = vu_mem_region_map(&d, fd1, &r);
	CHECK(!ret && !vu_mem_add(mem, &r), "first region added");
	d.guest_phys_addr = 0x100000 + TEST_SIZE;
	d.userspace_addr = 0x7e0000000000ULL;
	ret = vu_mem_region_map(&d, fd2, &r);
	CHECK(!ret && !vu_mem_add(mem, &r), "adjacent region added");

	TEST_STEP("overlapping regions are refused");
	r.gpa = 0x100000 + TEST_SIZE - 1;
	r.uaddr = 0x7d0000000000ULL;
	CHECK(vu_mem_add(mem, &r) == -EEXIST, "guest overlap refused");
	r.gpa = 0x800000;
	r.uaddr = 0x7e0000000000ULL + TEST_SIZE - 1;
	CHECK(vu_mem_add(mem, &r) == -EEXIST, "front-end overlap refused");
	r.gpa = 0x100000 - TEST_SIZE + 1;
	r.uaddr = 0x7d0000000000ULL;
	CHECK(vu_mem_add(mem, &r) == -EEXIST, "overlap from below refused");

	TEST_STEP("translation at the edges of a region");
	p = vu_mem_gpa(mem, 0x100000, &avail);
	CHECK(p && avail == TEST_SIZE, "first byte, %llu bytes on",
	      (unsigned long long)avail);
	p = vu_mem_gpa(mem, 0x100000 + TEST_SIZE - 1, &avail);
	CHECK(p && avail == 1, "last byte of the first region");
	p = vu_mem_gpa(mem, 0x100000 + 2 * TEST_SIZE, &avail);
	CHECK(!p, "byte behind the second region");
	p = vu_mem_gpa(mem, 0xfffff, &avail);
	CHECK(!p, "byte before the first region");
	p = vu_mem_gpa(mem, UINT64_MAX, &avail);
	CHECK(!p, "the last guest address");

	CHECK(vu_mem_uva(mem, 0x7f0000000000ULL, TEST_SIZE) != NULL,
	      "a whole region by front-end address");
	CHECK(!vu_mem_uva(mem, 0x7f0000000000ULL, TEST_SIZE + 1),
	      "one byte too much");
	CHECK(!vu_mem_uva(mem, 0x7f0000000000ULL + TEST_SIZE - 8, UINT64_MAX),
	      "a length wrapping around");
	CHECK(!vu_mem_uva(mem, 0x7f0000000000ULL - 1, 2),
	      "a range starting before the region");

	TEST_STEP("ranges spanning the two regions");
	CHECK(vu_mem_covers_gpa(mem, 0x100000, 2 * TEST_SIZE),
	      "both regions covered");
	CHECK(!vu_mem_covers_gpa(mem, 0x100000, 2 * TEST_SIZE + 1),
	      "one byte beyond");
	CHECK(!vu_mem_covers_gpa(mem, 0x100000, 0), "an empty range");
	CHECK(!vu_mem_covers_gpa(mem, 0x100000 + 8, UINT64_MAX),
	      "a range wrapping around");

	memset(vu_mem_gpa(mem, 0x100000 + TEST_SIZE - 32, &avail), 0x11, 32);
	memset(vu_mem_gpa(mem, 0x100000 + TEST_SIZE, &avail), 0x22, 32);
	CHECK(!vu_mem_read_gpa(mem, 0x100000 + TEST_SIZE - 32, buf, 64),
	      "read across the regions");
	CHECK(buf[0] == 0x11 && buf[31] == 0x11 && buf[32] == 0x22 &&
		      buf[63] == 0x22,
	      "the bytes of both regions");
	CHECK(vu_mem_read_gpa(mem, 0x100000 + 2 * TEST_SIZE - 32, buf, 64) ==
		      -EFAULT,
	      "read beyond the second region");

	TEST_STEP("removing a region");
	CHECK(vu_mem_remove(mem, 0x100000, 0x7f0000000000ULL + 1, TEST_SIZE,
			    &removed) == -ENOENT,
	      "another front-end address does not match");
	CHECK(!vu_mem_remove(mem, 0x100000, 0x7f0000000000ULL, TEST_SIZE,
			     &removed),
	      "the first region removed");
	vu_mem_region_unmap(&removed);
	CHECK(!vu_mem_gpa(mem, 0x100000, &avail), "nothing left there");
	CHECK(vu_mem_gpa(mem, 0x100000 + TEST_SIZE, &avail) != NULL,
	      "the second region is still there");
	vu_mem_clear(mem);

	TEST_STEP("a full table");
	memset(&r, 0, sizeof(r));
	r.size = 1;
	for (i = 0; i < VU_MEM_MAX_REGIONS; i++) {
		r.gpa = i;
		r.uaddr = i;
		if (vu_mem_add(mem, &r))
			break;
	}
	CHECK(i == VU_MEM_MAX_REGIONS, "%u regions taken", i);
	r.gpa = r.uaddr = 0x10000;
	CHECK(vu_mem_add(mem, &r) == -ENOSPC, "one more refused");
	/* Nothing of these is mapped */
	mem->nregions = 0;

	free(mem);
}

int main(void)
{
	int fd1 = test_memfd(TEST_SIZE), fd2 = test_memfd(TEST_SIZE);

	if (fd1 < 0 || fd2 < 0) {
		printf("memfd_create failed\n");
		return 1;
	}

	test_region_checks(fd1);
	test_translation(fd1, fd2);

	close(fd1);
	close(fd2);

	if (test_failures) {
		printf("FAIL: %u checks failed\n", test_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
