/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "util-debug.h"
#include "util-misc.h"

#define PARSE_REGEX "^\\s*(\\d+(?:.\\d+)?)\\s*([a-zA-Z]{2})?\\s*$"
static pcre2_code *parse_regex = NULL;
static pcre2_match_data *parse_regex_match = NULL;

void ParseSizeInit(void)
{
    int en;
    PCRE2_SIZE eo;
    int opts = 0;

    parse_regex =
            pcre2_compile((PCRE2_SPTR8)PARSE_REGEX, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (parse_regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                PARSE_REGEX, (int)eo, errbuffer);
        exit(EXIT_FAILURE);
    }
    parse_regex_match = pcre2_match_data_create_from_pattern(parse_regex, NULL);
}

void ParseSizeDeinit(void)
{
    pcre2_code_free(parse_regex);
    pcre2_match_data_free(parse_regex_match);
}

/* size string parsing API */

static int ParseSizeString(const char *size, double *res)
{
    int pcre2_match_ret;
    int r;
    int retval = 0;
    char str[128];
    char str2[128];

    *res = 0;

    if (size == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS,"invalid size argument - NULL. Valid size "
                   "argument should be in the format - \n"
                   "xxx <- indicates it is just bytes\n"
                   "xxxkb or xxxKb or xxxKB or xxxkB <- indicates kilobytes\n"
                   "xxxmb or xxxMb or xxxMB or xxxmB <- indicates megabytes\n"
                   "xxxgb or xxxGb or xxxGB or xxxgB <- indicates gigabytes.\n"
			    );
        retval = -2;
        goto end;
    }

    pcre2_match_ret = pcre2_match(
            parse_regex, (PCRE2_SPTR8)size, strlen(size), 0, 0, parse_regex_match, NULL);

    if (!(pcre2_match_ret == 2 || pcre2_match_ret == 3)) {
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

    size_t copylen = sizeof(str);
    r = pcre2_substring_copy_bynumber(parse_regex_match, 1, (PCRE2_UCHAR8 *)str, &copylen);
    if (r < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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

    if (pcre2_match_ret == 3) {
        copylen = sizeof(str2);
        r = pcre2_substring_copy_bynumber(parse_regex_match, 2, (PCRE2_UCHAR8 *)str2, &copylen);

        if (r < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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

    if (temp_res > (double) UINT64_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

void ShortenString(const char *input,
    char *output, size_t output_size, char c)
{
    const size_t str_len = strlen(input);
    size_t half = (output_size - 1) / 2;

    /* If the output size is an even number */
    if (half * 2 == (output_size - 1)) {
        half = half - 1;
    }

    size_t spaces = (output_size - 1) - (half * 2);

    /* Add the first half to the new string */
    snprintf(output, half+1, "%s", input);

    /* Add the amount of spaces wanted */
    size_t length = half;
    for (size_t i = half; i < half + spaces; i++) {
        char s[2] = "";
        snprintf(s, sizeof(s), "%c", c);
        length = strlcat(output, s, output_size);
    }

    snprintf(output + length, half + 1, "%s", input + (str_len - half));
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

void UtilMiscRegisterTests(void)
{
    UtRegisterTest("UtilMiscParseSizeStringTest01",
                   UtilMiscParseSizeStringTest01);
}
#endif /* UNITTESTS */
