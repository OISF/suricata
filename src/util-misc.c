/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "config.h"
#include "suricata.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-misc.h"

#define PARSE_REGEX "^\\s*(\\d+(?:.\\d+)?)\\s*([a-zA-Z]{2})?\\s*$"
static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

void ParseSizeInit(void)
{
    const char *eb = NULL;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset "
                   "%" PRId32 ": %s", PARSE_REGEX, eo, eb);
        exit(EXIT_FAILURE);
    }
    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        exit(EXIT_FAILURE);
    }
}

void ParseSizeDeinit(void)
{

    if (parse_regex != NULL)
        pcre_free(parse_regex);
    if (parse_regex_study != NULL)
        pcre_free_study(parse_regex_study);
}

/* size string parsing API */

static int ParseSizeString(const char *size, double *res)
{
#define MAX_SUBSTRINGS 30
    int pcre_exec_ret;
    int r;
    int ov[MAX_SUBSTRINGS];
    int retval = 0;
    char str[128];
    char str2[128];

    *res = 0;

    pcre_exec_ret = pcre_exec(parse_regex, parse_regex_study, size, strlen(size), 0, 0,
                    ov, MAX_SUBSTRINGS);
    if (!(pcre_exec_ret == 2 || pcre_exec_ret == 3)) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid size argument - %s. Valid size "
                   "argument should be in the format - \n"
                   "xxx <- indicates it is just bytes\n"
                   "xxxkb or xxxKb or xxxKB or xxxkB <- indicates kilobytes\n"
                   "xxxmb or xxxMb or xxxMB or xxxmB <- indicates megabytes\n"
                   "xxxgb or xxxGb or xxxGB or xxxgB <- indicates gigabytes.\n",
                   size);
        retval = -2;
        goto end;
    }

    r = pcre_copy_substring((char *)size, ov, MAX_SUBSTRINGS, 1,
                             str, sizeof(str));
    if (r < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        retval = -2;
        goto end;
    }

    char *endptr, *str_ptr = str;
    errno = 0;
    *res = strtod(str_ptr, &endptr);
    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        retval = -1;
        goto end;
    } else if (endptr == str_ptr) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        retval = -1;
        goto end;
    }

    if (pcre_exec_ret == 3) {
        r = pcre_copy_substring((char *)size, ov, MAX_SUBSTRINGS, 2,
                                 str2, sizeof(str2));
        if (r < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            retval = -2;
            goto end;
        }

        if (strcasecmp(str2, "kb") == 0) {
            *res *= 1024;
        } else if (strcasecmp(str2, "mb") == 0) {
            *res *= 1024 * 1024;
        } else if (strcasecmp(str2, "gb") == 0) {
            *res *= 1024 * 1024 * 1024;
        } else {
            /* Bad unit. */
            retval = -1;
            goto end;
        }
    }

    retval = 0;
end:
    return retval;
}

int ParseSizeStringU8(const char *size, uint8_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT8_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

int ParseSizeStringU16(const char *size, uint16_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT16_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

int ParseSizeStringU32(const char *size, uint32_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT32_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

int ParseSizeStringU64(const char *size, uint64_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT64_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

/*********************************Unittests********************************/

#ifdef UNITTESTS

static int UtilMiscParseSizeStringTest01(void)
{
    const char *str;
    double result;

    /* no space */

    str = "10";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = "10kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = "10gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240UL) {
        goto error;
    }


    /* space start */

    str = " 10";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = " 10kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = " 10gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }

    /* space end */

    str = "10 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = "10kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = "10gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }

    /* space start - space end */

    str = " 10 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = " 10kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = " 10gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }


    /* space between number and scale */

    /* no space */

    str = "10";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = "10 kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = "10 gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }


    /* space start */

    str = " 10";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = " 10 kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = " 10 gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }

    /* space end */

    str = "10 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = "10 kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = "10 mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = "10 gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }

    /* space start - space end */

    str = " 10 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10) {
        goto error;
    }

    str = " 10 kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024) {
        goto error;
    }

    str = " 10 mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10 * 1024 * 1024) {
        goto error;
    }

    str = " 10 gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10737418240) {
        goto error;
    }

    /* no space */

    str = "10.5";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = "10.5kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = "10.5gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }


    /* space start */

    str = " 10.5";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = " 10.5kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = " 10.5gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }

    /* space end */

    str = "10.5 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = "10.5kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = "10.5gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }

    /* space start - space end */

    str = " 10.5 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = " 10.5kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = " 10.5gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }


    /* space between number and scale */

    /* no space */

    str = "10.5";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = "10.5 kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = "10.5 gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }


    /* space start */

    str = " 10.5";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = " 10.5 kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 Kb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 KB";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 mb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = " 10.5 gb";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }

    /* space end */

    str = "10.5 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = "10.5 kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = "10.5 mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = "10.5 gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }

    /* space start - space end */

    str = " 10.5 ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5) {
        goto error;
    }

    str = " 10.5 kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 Kb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 KB ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024) {
        goto error;
    }

    str = " 10.5 mb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024) {
        goto error;
    }

    str = " 10.5 gb ";
    result = 0;
    if (ParseSizeString(str, &result) > 0) {
        goto error;
    }
    if (result != 10.5 * 1024 * 1024 * 1024) {
        goto error;
    }

    /* Should fail on unknown units. */
    if (ParseSizeString("32eb", &result) > 0) {
        goto error;
    }

    return 1;
 error:
    return 0;
}

#endif /* UNITTESTS */

void UtilMiscRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("UtilMiscParseSizeStringTest01",
                   UtilMiscParseSizeStringTest01);
#endif /* UNITTESTS */

    return;
}
