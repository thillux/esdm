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

#ifndef _LEAK_CHECK_H
#define _LEAK_CHECK_H

/* Does LeakSanitizer check this process for leaks when it exits? */
#if defined(__SANITIZE_ADDRESS__)
#define ESDM_LEAK_CHECK_AT_EXIT
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(leak_sanitizer)
#define ESDM_LEAK_CHECK_AT_EXIT
#endif
#endif

#ifdef ESDM_LEAK_CHECK_AT_EXIT
#include <sanitizer/lsan_interface.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The heap object @p is left to the end of the process on purpose, along with
 * what it refers to. Where it is kept reachable may be gone by the time the
 * leak checker looks - a library unloaded at the exit, say -, so LeakSanitizer
 * is told so.
 */
static inline void esdm_leak_intended(const void *p)
{
#ifdef ESDM_LEAK_CHECK_AT_EXIT
	__lsan_ignore_object(p);
#else
	(void)p;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* _LEAK_CHECK_H */
