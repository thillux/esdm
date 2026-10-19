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
 * A stand-in ESDM on the unprivileged RPC socket, serving the random number
 * calls of the daemon under test with a stream the test can predict, and held
 * unseeded on request - which a real ESDM cannot be made to be for long, and
 * which needs no root.
 */

#ifndef VU_STANDIN_H
#define VU_STANDIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Listen on the unprivileged socket and serve it from a thread. Returns 0, or
 * < 0 if the socket is somebody else's or cannot be bound - the test cannot
 * run then.
 */
int standin_start(void);
void standin_stop(void);

/*
 * Stop serving, and leave the socket behind with nobody listening on it, as an
 * esdm-server stopped with its socket units leaves it: every connection is
 * refused. standin_start() takes it over again.
 */
int standin_stop_refusing(void);

/* Whether the fully seeded and the prediction resistant DRNG serve */
void standin_set_seeded(bool seeded);

/* Byte @pos of the stream the stand-in serves - never FE_CANARY */
uint8_t standin_stream_byte(uint64_t pos);

/* Bytes of the stream served so far */
uint64_t standin_pos(void);

/* Requests of the fully seeded and the prediction resistant DRNG served */
unsigned int standin_full_requests(void);
unsigned int standin_pr_requests(void);

#endif /* VU_STANDIN_H */
