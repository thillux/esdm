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
 * A PKCS#11 module for the tests of esdm-es-pkcs11, standing in front of a
 * real one - SoftHSM - and passing everything on to it, but for three calls:
 *
 * - C_Login is recorded, one line per call with its result, in the file
 *   $ESDM_PKCS11_SHIM_LOG. SoftHSM counts no PIN retries, so this is how a test
 *   tells that a PIN the token refused is not tried again. It fails with
 *   CKR_DEVICE_ERROR, without asking SoftHSM, while the file
 *   $ESDM_PKCS11_SHIM_FAIL_LOGIN exists, as a token failing for another
 *   reason than the PIN does.
 * - C_GetTokenInfo reports the user PIN on its final try while the file
 *   $ESDM_PKCS11_SHIM_FINAL_TRY exists, as a token does after all but one
 *   of its PIN retries were used up, which SoftHSM never does.
 * - C_GenerateRandom fails with CKR_DEVICE_ERROR while the file
 *   $ESDM_PKCS11_SHIM_FAIL exists, as a smartcard pulled mid-request does,
 *   and hands out the same bytes every time while the file
 *   $ESDM_PKCS11_SHIM_REPEAT exists, as a broken noise source does.
 *
 * The real module is $ESDM_PKCS11_SHIM_MODULE. The PKCS#11 types are spelled
 * out here rather than taken from a pkcs11.h, which no dependency of the ESDM
 * installs: the function list of PKCS#11 2.40 is a version followed by the 68
 * functions, and the calls are found in it by the addresses the real module
 * exports them under rather than by their position.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_USER_TYPE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned char CK_BYTE;

#define CKR_GENERAL_ERROR 0x05UL
#define CKR_DEVICE_ERROR 0x30UL
#define CKF_USER_PIN_FINAL_TRY 0x00020000UL

/*
 * The start of CK_TOKEN_INFO, up to the flags: the label, the manufacturer,
 * the model and the serial number come first, as blank padded text
 */
struct ck_token_info_head {
	CK_BYTE text[32 + 32 + 16 + 16];
	unsigned long flags;
};

typedef struct {
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;

typedef void (*ck_fn)(void);

#define CK_FUNCTIONS 68

struct ck_function_list {
	CK_VERSION version;
	ck_fn fn[CK_FUNCTIONS];
};

typedef CK_RV (*ck_get_function_list)(struct ck_function_list **list);
typedef CK_RV (*ck_login)(CK_SESSION_HANDLE session, CK_USER_TYPE user,
			  CK_BYTE *pin, CK_ULONG pin_len);
typedef CK_RV (*ck_generate_random)(CK_SESSION_HANDLE session, CK_BYTE *data,
				    CK_ULONG len);
typedef CK_RV (*ck_get_token_info)(CK_SLOT_ID slot,
				   struct ck_token_info_head *info);

static struct ck_function_list shim_list;
static ck_login real_login;
static ck_generate_random real_generate_random;
static ck_get_token_info real_get_token_info;

/* Does the file named by the environment variable @var exist? */
static int shim_file(const char *var)
{
	const char *path = getenv(var);

	return path && !access(path, F_OK);
}

static CK_RV shim_login(CK_SESSION_HANDLE session, CK_USER_TYPE user,
			CK_BYTE *pin, CK_ULONG pin_len)
{
	const char *log = getenv("ESDM_PKCS11_SHIM_LOG");
	CK_RV rv = shim_file("ESDM_PKCS11_SHIM_FAIL_LOGIN") ?
			   CKR_DEVICE_ERROR :
			   real_login(session, user, pin, pin_len);

	if (log) {
		int fd = open(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
			      0600);

		if (fd >= 0) {
			char line[64];
			int len = snprintf(line, sizeof(line),
					   "C_Login user %lu rv 0x%lx\n", user,
					   rv);

			if (len > 0 && write(fd, line, (size_t)len) < 0)
				rv = CKR_GENERAL_ERROR;
			close(fd);
		}
	}

	return rv;
}

static CK_RV shim_get_token_info(CK_SLOT_ID slot,
				 struct ck_token_info_head *info)
{
	CK_RV rv = real_get_token_info(slot, info);

	if (!rv && shim_file("ESDM_PKCS11_SHIM_FINAL_TRY"))
		info->flags |= CKF_USER_PIN_FINAL_TRY;
	return rv;
}

static CK_RV shim_generate_random(CK_SESSION_HANDLE session, CK_BYTE *data,
				  CK_ULONG len)
{
	const char *fail = getenv("ESDM_PKCS11_SHIM_FAIL");
	const char *repeat = getenv("ESDM_PKCS11_SHIM_REPEAT");

	if (fail && !access(fail, F_OK))
		return CKR_DEVICE_ERROR;
	if (repeat && !access(repeat, F_OK)) {
		memset(data, 0x5a, len);
		return 0;
	}
	return real_generate_random(session, data, len);
}

/* The function @name of @handle, NULL if there is none */
static ck_fn shim_sym(void *handle, const char *name)
{
	void *sym = dlsym(handle, name);
	ck_fn fn;

	/* An object pointer is no function pointer to ISO C */
	memcpy(&fn, &sym, sizeof(fn));
	return sym ? fn : NULL;
}

/* Replace the function at @real in the list by @shim, false if it is none */
static int shim_replace(ck_fn real, ck_fn shim)
{
	unsigned int i;

	for (i = 0; i < CK_FUNCTIONS; i++) {
		if (shim_list.fn[i] == real) {
			shim_list.fn[i] = shim;
			return 1;
		}
	}
	return 0;
}

/* What the module exports, all libp11 looks for in it */
__attribute__((visibility("default"))) CK_RV
C_GetFunctionList(struct ck_function_list **list);

CK_RV C_GetFunctionList(struct ck_function_list **list)
{
	const char *module = getenv("ESDM_PKCS11_SHIM_MODULE");
	struct ck_function_list *real;
	ck_fn get, login, generate, token_info;
	void *handle;

	if (!list || !module)
		return CKR_GENERAL_ERROR;

	/* Never unloaded: the list handed out points into it */
	handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (!handle)
		return CKR_GENERAL_ERROR;

	get = shim_sym(handle, "C_GetFunctionList");
	login = shim_sym(handle, "C_Login");
	generate = shim_sym(handle, "C_GenerateRandom");
	token_info = shim_sym(handle, "C_GetTokenInfo");
	if (!get || !login || !generate || !token_info ||
	    ((ck_get_function_list)get)(&real) || !real)
		return CKR_GENERAL_ERROR;

	memcpy(&shim_list, real, sizeof(shim_list));
	real_login = (ck_login)login;
	real_generate_random = (ck_generate_random)generate;
	real_get_token_info = (ck_get_token_info)token_info;
	if (!shim_replace(login, (ck_fn)shim_login) ||
	    !shim_replace(generate, (ck_fn)shim_generate_random) ||
	    !shim_replace(token_info, (ck_fn)shim_get_token_info))
		return CKR_GENERAL_ERROR;

	*list = &shim_list;
	return 0;
}
