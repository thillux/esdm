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

#ifndef ESDM_ES_EVENTS_H
#define ESDM_ES_EVENTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The system events the kernel module esdm_es reports (ESDM_ES_EVENTS of
 * esdm_es_ioctl.h): a changed VM generation, suspend, resume and shutdown.
 *
 * esdm_es_events_start() opens /dev/esdm_es, which takes CAP_SYS_ADMIN, and
 * starts a thread that waits for the events - call it before the privileges
 * are dropped. Without the module, or with one that does not report events,
 * nothing is started: esdm-server-signal-helper then remains the way to tell
 * the ESDM about suspend and resume. esdm_es_events_stop() ends the thread.
 */
void esdm_es_events_start(void);
void esdm_es_events_stop(void);

/*
 * Act on the events counted between @seen and @now, both arrays of
 * ESDM_ES_EVENT_LAST counts, of which @supported names the valid ones.
 * Returns the number of event types acted on.
 */
unsigned int esdm_es_events_handle(uint32_t supported, const uint32_t *seen,
				   const uint32_t *now);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_ES_EVENTS_H */
