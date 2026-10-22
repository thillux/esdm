/*
 * Test that at most one timing entropy source is credited
 *
 * The interrupt and scheduler based sources see dependent events, so setting a
 * rate for one of them zeroes the others. Two threads set the rates of two of
 * them at the same time, round after round, and afterwards one of the two
 * rates has to be zero.
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
#include <stdint.h>
#include <stdio.h>

#include "esdm_config.h"

/* Rounds the two setters race in */
#define ESDM_CTR_ROUNDS 20000

static pthread_barrier_t esdm_ctr_barrier;

static void *esdm_ctr_sched(void *arg)
{
	unsigned int i;

	(void)arg;

	for (i = 0; i < ESDM_CTR_ROUNDS; i++) {
		pthread_barrier_wait(&esdm_ctr_barrier);
		esdm_config_es_sched_entropy_rate_set(1);
		pthread_barrier_wait(&esdm_ctr_barrier);
		/* The main thread checks the outcome here */
		pthread_barrier_wait(&esdm_ctr_barrier);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t thread;
	unsigned int i;
	int ret = 0;

	(void)argc;
	(void)argv;

	if (pthread_barrier_init(&esdm_ctr_barrier, NULL, 2))
		return 1;

	if (pthread_create(&thread, NULL, esdm_ctr_sched, NULL))
		return 1;

	for (i = 0; i < ESDM_CTR_ROUNDS; i++) {
		pthread_barrier_wait(&esdm_ctr_barrier);
		esdm_config_es_irq_entropy_rate_set(1);
		pthread_barrier_wait(&esdm_ctr_barrier);

		if (!ret && esdm_config_es_irq_entropy_rate() &&
		    esdm_config_es_sched_entropy_rate()) {
			printf("Round %u: both the interrupt and the scheduler ES are credited\n",
			       i);
			ret = 1;
		}

		pthread_barrier_wait(&esdm_ctr_barrier);
	}

	pthread_join(thread, NULL);
	pthread_barrier_destroy(&esdm_ctr_barrier);

	return ret;
}
