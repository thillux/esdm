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
 * PKCS#11 entropy source against a real token.
 *
 * es_pkcs11_test.c only checks the callbacks without a token, which is the
 * situation on most build machines: it passes with the source switched off, so
 * nothing downstream of a bound slot is ever executed. SoftHSM needs no
 * hardware, so the interesting half can be tested too - discovering the slot,
 * selecting it by token label, logging in and pulling bytes out of
 * C_GenerateRandom. The token is created in a directory of this test's own, so
 * the run neither depends on nor disturbs any token on the machine.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"

#include "../es_state_check.h"

#define ES_IDX esdm_ext_es_pkcs11

/* Must match what the token below is initialized with */
#define TOKEN_LABEL "esdm-test-token"
#define TOKEN_PIN "648219"
#define TOKEN_SO_PIN "1234567890"
/* Label of a token created only after the source looked for it */
#define LATE_TOKEN_LABEL "esdm-late-token"

static unsigned int failures;
/* confpath holds tokendir plus a filename, so keep room for it */
static char tokendir[400];
static char confpath[512];

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL %s:%d: ", __func__, __LINE__);            \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			failures++;                                            \
		}                                                              \
	} while (0)

/*
 * Run softhsm2-util. Returns its exit status, or -1 if it could not be run at
 * all - the caller distinguishes "no SoftHSM here" (skip) from "SoftHSM is
 * here and refused" (fail).
 */
static int run_softhsm_util(char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;

	if (pid == 0) {
		/* Keep the log readable; failures are reported by the caller */
		int devnull = open("/dev/null", O_WRONLY);

		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execvp("softhsm2-util", argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/*
 * Build a SoftHSM configuration pointing at a token directory of our own and
 * initialize one token in it. Returns 0 on success, 77 when SoftHSM is not
 * available (the test then skips), 1 on a real failure.
 */
static int softhsm_setup(void)
{
	const char *tmpdir = getenv("TMPDIR");
	FILE *conf;
	char *argv[] = {
		(char *)"softhsm2-util", (char *)"--init-token",
		(char *)"--free",	(char *)"--label",
		(char *)TOKEN_LABEL,	(char *)"--so-pin",
		(char *)TOKEN_SO_PIN,	(char *)"--pin",
		(char *)TOKEN_PIN,	NULL
	};
	int ret;

	snprintf(tokendir, sizeof(tokendir), "%s/esdm-softhsm-%d",
		 tmpdir && *tmpdir ? tmpdir : "/tmp", (int)getpid());
	snprintf(confpath, sizeof(confpath), "%s/softhsm2.conf", tokendir);

	if (mkdir(tokendir, 0700) < 0) {
		printf("cannot create the token directory %s\n", tokendir);
		return 1;
	}

	conf = fopen(confpath, "w");
	if (!conf) {
		printf("cannot write %s\n", confpath);
		return 1;
	}
	fprintf(conf,
		"directories.tokendir = %s\n"
		"objectstore.backend = file\n"
		"log.level = ERROR\n",
		tokendir);
	if (fclose(conf)) {
		printf("cannot write %s\n", confpath);
		return 1;
	}

	/*
	 * Both softhsm2-util below and the module the ESDM loads read this,
	 * so it has to be in place before either runs.
	 */
	if (setenv("SOFTHSM2_CONF", confpath, 1) < 0) {
		printf("cannot set SOFTHSM2_CONF\n");
		return 1;
	}

	ret = run_softhsm_util(argv);
	if (ret == 127 || ret < 0) {
		printf("softhsm2-util is not available - skipping\n");
		return 77;
	}
	if (ret != 0) {
		printf("softhsm2-util --init-token failed with %d\n", ret);
		return 1;
	}

	return 0;
}

static void softhsm_teardown(void)
{
	/*
	 * Only ever removes what this test created, one directory level deep -
	 * SoftHSM puts one subdirectory per token below the token directory.
	 */
	DIR *d = opendir(tokendir);
	struct dirent *e;

	if (!d)
		return;

	while ((e = readdir(d))) {
		char path[1024];
		DIR *sub;
		struct dirent *se;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", tokendir, e->d_name);
		sub = opendir(path);
		if (!sub) {
			unlink(path);
			continue;
		}

		while ((se = readdir(sub))) {
			char subpath[2048];

			if (!strcmp(se->d_name, ".") ||
			    !strcmp(se->d_name, ".."))
				continue;
			snprintf(subpath, sizeof(subpath), "%.1000s/%.1000s",
				 path, se->d_name);
			unlink(subpath);
		}
		closedir(sub);
		rmdir(path);
	}
	closedir(d);
	rmdir(tokendir);
}

/* The source has to consider itself usable - the module path is compiled in */
static void test_active(void)
{
	CHECK(esdm_es[ES_IDX]->active && esdm_es[ES_IDX]->active(),
	      "the PKCS#11 source is inactive although a module is configured");
}

/*
 * Selecting the token by label is what a deployment with more than one token
 * relies on, and it is also what binds the slot in the first place.
 */
static void test_select_token(void)
{
	CHECK(esdm_es_pkcs11_set_token_label(TOKEN_LABEL) == 0,
	      "cannot select the SoftHSM token by its label");

	/*
	 * A label no token carries must be refused rather than silently
	 * leaving the previous slot in place - otherwise a typo in the
	 * configuration draws entropy from whatever token happens to be there.
	 */
	CHECK(esdm_es_pkcs11_set_token_label("esdm-no-such-token") != 0,
	      "an unknown token label was accepted");

	/* Put the good one back for the tests that follow */
	CHECK(esdm_es_pkcs11_set_token_label(TOKEN_LABEL) == 0,
	      "cannot re-select the SoftHSM token");
}

/*
 * Every failed login uses up one of the PIN retries of a token, which then
 * locks the PIN. A wrong PIN was kept and tried again on every re-open and on
 * every look-up for a token, every ESDM_PKCS11_RETRY_INTERVAL_SEC - a mistyped
 * esdm-tool --pkcs11-pin locked a smartcard within seconds. The token refuses
 * it once, and then it is gone.
 */
static void test_wrong_pin(void)
{
	CHECK(esdm_es_pkcs11_set_pin("000000") == -EACCES,
	      "a wrong PIN was not refused");

	/* The re-open logged in with the refused PIN again */
	CHECK(esdm_es_pkcs11_set_token_label(TOKEN_LABEL) == 0,
	      "the refused PIN was tried again");
}

static void test_login(void)
{
	CHECK(esdm_es_pkcs11_set_pin(TOKEN_PIN) == 0,
	      "login with the token PIN failed");
}

/* With a slot bound, the source must credit the configured rate */
static void test_entropy_level(void)
{
	uint32_t maxe = esdm_es[ES_IDX]->max_entropy();
	uint32_t curr = esdm_es[ES_IDX]->curr_entropy(esdm_security_strength());
	uint32_t rate = esdm_config_es_pkcs11_entropy_rate();

	CHECK(maxe == curr, "max_entropy (%u) disagrees with curr_entropy (%u)",
	      maxe, curr);

	if (rate)
		CHECK(maxe > 0,
		      "no entropy credited although a token is bound and the rate is %u",
		      rate);
}

/*
 * The point of the source: bytes actually come out of the token, and they are
 * bytes rather than a buffer nobody wrote to.
 */
static void test_get_entropy(void)
{
	struct entropy_es eb_es;
	unsigned int i, zero = 0;
	uint32_t rate = esdm_config_es_pkcs11_entropy_rate();

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	CHECK(eb_es.e_bits <= ESDM_DRNG_INIT_SEED_SIZE_BITS,
	      "over-credited: %u bits for a %u bit request", eb_es.e_bits,
	      ESDM_DRNG_INIT_SEED_SIZE_BITS);

	if (rate)
		CHECK(eb_es.e_bits > 0,
		      "the token delivered no credited entropy");

	for (i = 0; i < ESDM_DRNG_INIT_SEED_SIZE_BITS / 8; i++) {
		if (!eb_es.e[i])
			zero++;
	}
	CHECK(zero < ESDM_DRNG_INIT_SEED_SIZE_BITS / 8,
	      "the buffer the token filled is all zero");

	printf("token delivered %u credited bits, %u of %u bytes zero\n",
	       eb_es.e_bits, zero, ESDM_DRNG_INIT_SEED_SIZE_BITS / 8);
}

/* Two draws in a row must not return the same bytes */
static void test_get_entropy_differs(void)
{
	struct entropy_es first, second;

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));

	esdm_es[ES_IDX]->get_ent(&first, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	esdm_es[ES_IDX]->get_ent(&second, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	CHECK(memcmp(first.e, second.e, ESDM_DRNG_INIT_SEED_SIZE_BITS / 8) != 0,
	      "two consecutive draws from the token returned identical data");
}

/* The status report has to name the token that is actually in use */
static void test_state(void)
{
	struct json_object *state = es_state_get(esdm_es[ES_IDX]);

	CHECK(es_state_has(state, "available_entropy", json_type_int),
	      "state malformed: %s", es_state_print(state));
	CHECK(es_state_str_is(state, "token", TOKEN_LABEL),
	      "state does not name the bound token: %s", es_state_print(state));
	CHECK(es_state_str(state, "module") &&
		      !es_state_str_is(state, "module", "(unset)"),
	      "state reports no module although one is configured: %s",
	      es_state_print(state));

	json_object_put(state);
}

/*
 * Clearing the runtime overrides must not leave the source wedged: an empty
 * string falls back to the compile-time defaults, and the source has to keep
 * answering either way.
 */
static void test_clear_overrides(void)
{
	struct json_object *state;

	CHECK(esdm_es_pkcs11_set_pin("") == 0, "clearing the PIN failed");

	/*
	 * Clearing the label re-opens against the compile-time default, which
	 * is empty in this build - the first usable slot is then taken, and
	 * SoftHSM has exactly one. Whatever it decides, asking for the state
	 * afterwards must still work.
	 */
	(void)esdm_es_pkcs11_set_token_label("");

	state = es_state_get(esdm_es[ES_IDX]);
	CHECK(es_state_has(state, "available_entropy", json_type_int),
	      "state malformed after clearing the overrides: %s",
	      es_state_print(state));
	json_object_put(state);
}

/*
 * A token that is not there - pulled, or not inserted yet - has to be picked
 * up once it is, without a reinitialization. Only the monitor of a build with
 * the block cache once looked for it again, and an SP800-90C build compiles
 * that out. Here the token turns up as a second one created in SoftHSM.
 */
static void test_token_appears(void)
{
	char *argv[] = { (char *)"softhsm2-util",  (char *)"--init-token",
			 (char *)"--free",	   (char *)"--label",
			 (char *)LATE_TOKEN_LABEL, (char *)"--so-pin",
			 (char *)TOKEN_SO_PIN,	   (char *)"--pin",
			 (char *)TOKEN_PIN,	   NULL };
	struct entropy_es eb_es;
	struct json_object *state;

	CHECK(esdm_es_pkcs11_set_token_label(LATE_TOKEN_LABEL) != 0,
	      "a token label nobody carries yet was accepted");

	/* Spends the first retry, which finds nothing */
	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	CHECK(eb_es.e_bits == 0, "%u bits credited without a token",
	      eb_es.e_bits);

	CHECK(run_softhsm_util(argv) == 0, "cannot create the second token");

	/* Within the retry interval it is not looked for */
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	state = es_state_get(esdm_es[ES_IDX]);
	CHECK(!es_state_str_is(state, "token", LATE_TOKEN_LABEL),
	      "the token was looked for again within the retry interval: %s",
	      es_state_print(state));
	json_object_put(state);

	sleep(ESDM_PKCS11_RETRY_INTERVAL_SEC + 1);

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	state = es_state_get(esdm_es[ES_IDX]);
	CHECK(es_state_str_is(state, "token", LATE_TOKEN_LABEL),
	      "the token that turned up was not picked up: %s",
	      es_state_print(state));
	json_object_put(state);
	if (esdm_config_es_pkcs11_entropy_rate())
		CHECK(eb_es.e_bits > 0,
		      "the token that turned up delivered no entropy");
}

static void test_reject_null(void)
{
	CHECK(esdm_es_pkcs11_set_pin(NULL) == -EINVAL,
	      "a NULL PIN was not rejected with -EINVAL");
	CHECK(esdm_es_pkcs11_set_token_label(NULL) == -EINVAL,
	      "a NULL token label was not rejected with -EINVAL");
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = softhsm_setup();
	if (ret)
		return ret;

	if (esdm_es[ES_IDX]->init()) {
		printf("the PKCS#11 entropy source failed to initialize against SoftHSM\n");
		softhsm_teardown();
		return 1;
	}

	test_active();
	test_select_token();
	/* Before the login: a token logged in to is not logged in to again */
	test_wrong_pin();
	test_login();
	test_entropy_level();
	test_get_entropy();
	test_get_entropy_differs();
	test_state();
	test_reject_null();
	test_token_appears();
	/* Last: it drops the overrides the tests above rely on */
	test_clear_overrides();

	esdm_es[ES_IDX]->fini();
	softhsm_teardown();

	if (failures) {
		printf("es_pkcs11_softhsm: %u check(s) FAILED\n", failures);
		return 1;
	}
	printf("es_pkcs11_softhsm: all checks passed\n");
	return 0;
}
