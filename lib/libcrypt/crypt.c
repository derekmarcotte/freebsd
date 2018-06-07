/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 Mark Murray
 * Copyright (c) 2014 Dag-Erling Smørgrav
 * Copyright (c) 2015 Derek Marcotte
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY MARK MURRAY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL MARK MURRAY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>

#include <libutil.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>

#include "crypt.h"

/*
 * List of supported crypt(3) formats.
 *
 * Ordered from most probable to least probable[1], for the find algorithm to 
 * preform a little better in some cases.  Generally, order is not important.
 *
 * 1. as guessed by a random person
 *
 */
static const struct crypt_format {
	const char *name;
	int (*func)(const char *, const char *, char *);
	const char *magic;
	const char *const default_format;
	const char *const format_regex;
	
	const uint8_t salt_bytes;
	const bool salt_trailing_sign;	/* do we tack on a $ at the end of the salt */
} crypt_formats[] = {
	{ "md5",	crypt_md5,	"$1$",	"$1$",		"^\\$1\\$$",				8,	true	},
	{ "sha512",	crypt_sha512,	"$6$",	"$6$",		"^\\$6\\$(rounds=[0-9]{0,9}\\$)?$",	16,	true	},
#ifdef HAS_BLOWFISH
	{ "blf",	crypt_blowfish,	"$2",	"$2b$04$",	"^\\$2[ab]?\\$[0-9]{2}\\$$",		22 /* 16 * 1.333 */,	false	},
#endif
#ifdef HAS_DES
	{ "des",	crypt_des,	NULL,	"",		NULL,					2,	false	},
	{ "des-ext",	crypt_des,	"_",	"_..T.",	"^_[A-Za-z0-9./]{4}$",			4,	false	},
#endif
	{ "nth",	crypt_nthash,	"$3$",	"$3$",		"^\\$3\\$$",				0,	false	},
	{ "sha256",	crypt_sha256,	"$5$",	"$5$",		"^\\$5\\$(rounds=[0-9]{0,9}\\$)?$",	16,	true	},
	
	/* sentinel */
	{ NULL,		NULL,		NULL,	NULL,		NULL,	0,	NULL	}
};

#ifdef HAS_DES
/* must be des if system has des */
static char default_format[256] = "des";
#else 
static char default_format[256] = "sha512";
#endif

/* local-scope only */
static const struct crypt_format *crypt_find_format(const char *);
static bool crypt_validate_format_regex(const char *, const char *);
static bool crypt_format_is_modular(const char*);

#define DES_SALT_ALPHABET \
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/*
 * Fill a buffer with a new salt conforming to a particular crypt format
 *
 * We're breaking the API convention established by crypt_set_format (return 0 
 * on success)  * because it might be nice to behave like the rest of C 
 * libraries, rather than the one deprecated function.
 *
 */
int
crypt_makesalt(char *out, const char *format, size_t *outlen)
{
	const struct crypt_format *cf;
	uint8_t rand_buf[4];
	size_t reqsz;
	const char *prefix;
	size_t prefix_len;
	
	/* diff really is a size, but keeping it api compatible with b64_from_24bit.  
	 * Only up to 4 bytes anyways, shouldn't be a problem, right? 
	 */
	int diff;
	unsigned int i;
	
	/* find the appropriate format entry */
	cf = crypt_find_format(format);
	if (cf == NULL )
		return (-1);
	
	/* calculate required output size */
	if (crypt_format_is_modular(format) ) {
		prefix = format;
	} else {
		prefix = cf->default_format;
	}
	prefix_len = strlen(prefix);
	reqsz = prefix_len + (size_t) cf->salt_bytes;
	
	if (cf->salt_trailing_sign)
		reqsz++;
	
	/* trailing '\0' */
	reqsz++;
	
	/* does the output buff have enough */
	if (reqsz > *outlen) {
		*outlen = reqsz;
		return (-2);
	}
	
	/* start building our output */
	strncpy(out, prefix, *outlen);
	out += prefix_len;
	
	for (i = 0; i < cf->salt_bytes; i += 4 ) {
		arc4random_buf(rand_buf, 3);
		
		diff = MIN(cf->salt_bytes - i, 4);
		b64_from_24bit(rand_buf[2], rand_buf[1], rand_buf[0], diff, &out);
	}
	
	/* cleanup */
	bzero(rand_buf, sizeof(rand_buf) );
	
	if (cf->salt_trailing_sign) {
		out[0] = '$';
		out++;
	}
	
	/* don't need to add trailing '\0', strncpy above will have set it already */
	return (0);
}

/*
 * Returns the name of the currently selected format.
 */
const char *
crypt_get_format(void)
{
	return default_format;
}

/*
 * Selects the format to use for subsequent crypt(3) invocations.
 */
int
crypt_set_format(const char *format)
{
	if (crypt_find_format(format) == NULL) {
		return (0);
	}
	
	strncpy(default_format, format, sizeof(default_format) );
	return (1);
}

/*
 * is the crypt format a recognized as valid
 */
static bool
crypt_format_validate_regex(const char* regex, const char *format) 
{
	regex_t regex_c;
	int res = 0;
	
	/* We could cache these, but they are simple, and this function won't be
	 * called often.
	 */
	if (regcomp(&regex_c, regex, REG_EXTENDED) != 0) {
		return false;
	}
	
	res = regexec(&regex_c, format, 0, NULL, 0);
	regfree(&regex_c);
	
	return !res;
}

/*
 * is the crypt format a fancy-dancy modular format
 */
static bool
crypt_format_is_modular(const char* format) 
{
	/* we'll treat 'new des' as modular, because they can set 24 bits of count via salt */
	return (format[0] == '$' || format[0] == '_');
}

/*
 * lookup our format in our internal table for a matching crypt_format structure
 */
static const struct crypt_format *
crypt_find_format(const char *format)
{
	const struct crypt_format *cf;
	
	if (strcmp(format, "default") == 0 ) {
		format = default_format;
	}
	
	if (crypt_format_is_modular(format) ) {
		/* modular crypt magic lookup, force full syntax */
		for (cf = crypt_formats; cf->name != NULL; ++cf) {
			if (cf->magic != NULL && strstr(format, cf->magic) == format && crypt_format_validate_regex(cf->format_regex, format) ) {
				return cf;
			}
		}
	} else {
		/* name lookup */
		for (cf = crypt_formats; cf->name != NULL; ++cf) {
			if (strcasecmp(cf->name, format) == 0) {
				return cf;
			}
		}
	}
	
	return NULL;
}

/*
 * Hash the given password with the given salt.  If the salt begins with a
 * magic string (e.g. "$6$" for sha512), the corresponding format is used;
 * otherwise, the currently selected format is used.
 */
char *
crypt_r(const char *passwd, const char *salt, struct crypt_data *data)
{
	const struct crypt_format *cf;
	int (*func)(const char *, const char *, char *);
#ifdef HAS_DES
	int len;
#endif
	
	/* use the magic in the salt for lookup */
	for (cf = crypt_formats; cf->name != NULL; ++cf)
		if (cf->magic != NULL && strstr(salt, cf->magic) == salt) {
			func = cf->func;
			goto match;
		}
#ifdef HAS_DES
	/* check if it's standard des */
	len = strlen(salt);
	if ((len == 13 || len == 2) && strspn(salt, DES_SALT_ALPHABET) == len) {
		func = crypt_des;
		goto match;
	}
#endif
	cf = crypt_find_format(default_format);
	func = cf->func;
match:
	if (func(passwd, salt, data->__buf) != 0)
		return (NULL);
	return (data->__buf);
}

char *
crypt(const char *passwd, const char *salt)
{
	static struct crypt_data data;

	return (crypt_r(passwd, salt, &data));
}
