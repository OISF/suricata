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
#include "suricata.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-misc.h"

#define PARSE_REGEX "^\\s*(\\d+(?:.\\d+)?)\\s*([a-zA-Z]{2,3})?\\s*$"
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
        SCLogError("pcre2 compile of \"%s\" failed at "
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
        SCLogError("invalid size argument: NULL. Valid input is <number><unit>. Unit can be "
                   "kb/KiB, mb/MiB or gb/GiB");
        retval = -2;
        goto end;
    }

    pcre2_match_ret = pcre2_match(
            parse_regex, (PCRE2_SPTR8)size, strlen(size), 0, 0, parse_regex_match, NULL);

    if (!(pcre2_match_ret == 2 || pcre2_match_ret == 3)) {
        SCLogError("invalid size argument: '%s'. Valid input is <number><unit>. Unit can be "
                   "kb/KiB, mb/MiB or gb/GiB",
                size);
        retval = -2;
        goto end;
    }

    size_t copylen = sizeof(str);
    r = pcre2_substring_copy_bynumber(parse_regex_match, 1, (PCRE2_UCHAR8 *)str, &copylen);
    if (r < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        retval = -2;
        goto end;
    }

    char *endptr, *str_ptr = str;
    errno = 0;
    *res = strtod(str_ptr, &endptr);
    if (errno == ERANGE) {
        SCLogError("Numeric value out of range");
        retval = -1;
        goto end;
    } else if (endptr == str_ptr) {
        SCLogError("Invalid numeric value");
        retval = -1;
        goto end;
    }

    if (pcre2_match_ret == 3) {
        copylen = sizeof(str2);
        r = pcre2_substring_copy_bynumber(parse_regex_match, 2, (PCRE2_UCHAR8 *)str2, &copylen);

        if (r < 0) {
            SCLogError("pcre2_substring_copy_bynumber failed");
            retval = -2;
            goto end;
        }

        if (strcasecmp(str2, "kb") == 0 || strcmp(str2, "KiB") == 0) {
            *res *= 1024;
        } else if (strcasecmp(str2, "mb") == 0 || strcmp(str2, "MiB") == 0) {
            *res *= 1024 * 1024;
        } else if (strcasecmp(str2, "gb") == 0 || strcmp(str2, "GiB") == 0) {
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

/**
 * \brief Parse a time string into seconds and set in res.
 * \return 0 on success, -1 on overflow, -2 on invalid format, -3 other error
 */
int ParseTimeStringU64(const char *entry, uint64_t *res)
{
    if (res == NULL) {
        return -3;
    }
    *res = 0;
    if (entry == NULL) {
        return -3;
    }
    const char *p = entry;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '\0')
        goto formaterr; // empty after spaces

    errno = 0;
    char *endptr = NULL;
    unsigned long long base = strtoull(p, &endptr, 10);
    if (errno == ERANGE) {
        goto overflow;
    }
    if (endptr == p) {
        goto formaterr; // no digits
    }

    while (isspace((unsigned char)*endptr))
        endptr++;
    char unitbuf[16];
    size_t ulen = 0;
    const char *up = endptr; // unit processing pointer
    while (*up && isalpha((unsigned char)*up) && ulen + 1 < sizeof(unitbuf)) {
        unitbuf[ulen++] = (char)tolower((unsigned char)*up);
        up++;
    }
    unitbuf[ulen] = '\0';
    /* Any non-space trailing characters invalidate */
    while (isspace((unsigned char)*up))
        up++;
    if (*up != '\0') {
        goto formaterr;
    }

    uint64_t multiplier = 1ULL;
    if (ulen != 0) {
        /* Match tokens by length then content to be efficient */
        switch (ulen) {
            case 1:
                if (unitbuf[0] == 's') {
                    multiplier = 1ULL;
                } else if (unitbuf[0] == 'm') {
                    multiplier = 60ULL;
                } else if (unitbuf[0] == 'h') {
                    multiplier = 3600ULL;
                } else if (unitbuf[0] == 'd') {
                    multiplier = 86400ULL;
                } else if (unitbuf[0] == 'w') {
                    multiplier = 604800ULL;
                } else if (unitbuf[0] == 'y') {
                    multiplier = 31536000ULL;
                } else {
                    goto formaterr;
                }
                break;
            case 2:
                if (memcmp(unitbuf, "hr", 2) == 0)
                    multiplier = 3600ULL;
                else
                    goto formaterr;
                break;
            case 3:
                if (memcmp(unitbuf, "sec", 3) == 0)
                    multiplier = 1ULL;
                else if (memcmp(unitbuf, "min", 3) == 0)
                    multiplier = 60ULL;
                else if (memcmp(unitbuf, "hrs", 3) == 0)
                    multiplier = 3600ULL;
                else if (memcmp(unitbuf, "day", 3) == 0)
                    multiplier = 86400ULL;
                else if (memcmp(unitbuf, "wks", 3) == 0)
                    multiplier = 604800ULL;
                else if (memcmp(unitbuf, "yrs", 3) == 0)
                    multiplier = 31536000ULL;
                else
                    goto formaterr;
                break;
            case 4:
                if (memcmp(unitbuf, "secs", 4) == 0)
                    multiplier = 1ULL;
                else if (memcmp(unitbuf, "hour", 4) == 0)
                    multiplier = 3600ULL;
                else if (memcmp(unitbuf, "days", 4) == 0)
                    multiplier = 86400ULL;
                else if (memcmp(unitbuf, "week", 4) == 0)
                    multiplier = 604800ULL;
                else if (memcmp(unitbuf, "year", 4) == 0)
                    multiplier = 31536000ULL;
                else
                    goto formaterr;
                break;
            case 5:
                if (memcmp(unitbuf, "hours", 5) == 0)
                    multiplier = 3600ULL;
                else if (memcmp(unitbuf, "weeks", 5) == 0)
                    multiplier = 604800ULL;
                else if (memcmp(unitbuf, "years", 5) == 0)
                    multiplier = 31536000ULL;
                else
                    goto formaterr;
                break;
            case 6:
                if (memcmp(unitbuf, "second", 6) == 0)
                    multiplier = 1ULL;
                else
                    goto formaterr;
                break;
            case 7:
                if (memcmp(unitbuf, "seconds", 7) == 0)
                    multiplier = 1ULL;
                else
                    goto formaterr;
                break;
            default:
                goto formaterr; /* unsupported */
        }
    }

    if (base > 0 && multiplier > UINT64_MAX / base) {
        goto overflow;
    }
    *res = (uint64_t)base * multiplier;
    return 0;

overflow:
    SCLogError("Time to convert \"%s\" is too big.", entry);
    return -1;

formaterr:
    SCLogError("Invalid time argument \"%s\". Valid input is <number><unit> (e.g. 10s, 5m, 2h)", entry);
    return -2;
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
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = "10kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = "10gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240UL);

    /* space start */

    str = " 10";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = " 10kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = " 10gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space end */

    str = "10 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = "10kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = "10gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space start - space end */

    str = " 10 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = " 10kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = " 10gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space between number and scale */

    /* no space */

    str = "10";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = "10 kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = "10 gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space start */

    str = " 10";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = " 10 kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = " 10 gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space end */

    str = "10 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = "10 kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = "10 mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = "10 gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* space start - space end */

    str = " 10 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10);

    str = " 10 kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024);

    str = " 10 mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10 * 1024 * 1024);

    str = " 10 gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10737418240);

    /* no space */

    str = "10.5";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = "10.5kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = "10.5gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space start */

    str = " 10.5";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = " 10.5kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = " 10.5gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space end */

    str = "10.5 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = "10.5kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = "10.5gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space start - space end */

    str = " 10.5 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = " 10.5kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = " 10.5gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space between number and scale */

    /* no space */

    str = "10.5";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = "10.5 kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = "10.5 gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space start */

    str = " 10.5";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = " 10.5 kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 Kb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 KB";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 mb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = " 10.5 gb";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space end */

    str = "10.5 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = "10.5 kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = "10.5 mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = "10.5 gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* space start - space end */

    str = " 10.5 ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5);

    str = " 10.5 kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 Kb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 KB ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 mb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = " 10.5 gb ";
    result = 0;
    FAIL_IF(ParseSizeString(str, &result) != 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    /* Should fail on unknown units. */
    FAIL_IF(ParseSizeString("32eb", &result) == 0);

    PASS;
}

static int UtilMiscParseSizeStringTest02(void)
{
    const char *str;
    double result;

    str = "10kib";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == -1);

    str = "10Kib";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == -1);

    str = "10KiB";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == 0);
    FAIL_IF(result != 10 * 1024);

    str = "10mib";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == -1);

    str = "10gib";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == -1);

    str = " 10.5 KiB ";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == 0);
    FAIL_IF(result != 10.5 * 1024);

    str = " 10.5 MiB ";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == 0);
    FAIL_IF(result != 10.5 * 1024 * 1024);

    str = " 10.5 GiB ";
    result = 0;
    FAIL_IF_NOT(ParseSizeString(str, &result) == 0);
    FAIL_IF(result != 10.5 * 1024 * 1024 * 1024);

    PASS;
}

static int UtilMiscParseTimeStringTest01(void)
{
    uint64_t v;
    FAIL_IF(ParseTimeStringU64("10", &v) != 0 || v != 10);
    FAIL_IF(ParseTimeStringU64("10s", &v) != 0 || v != 10);
    FAIL_IF(ParseTimeStringU64("10sec", &v) != 0 || v != 10);
    FAIL_IF(ParseTimeStringU64("2m", &v) != 0 || v != 120);
    FAIL_IF(ParseTimeStringU64("2 min", &v) != 0 || v != 120);
    FAIL_IF(ParseTimeStringU64("1h", &v) != 0 || v != 3600);
    FAIL_IF(ParseTimeStringU64("1 hour", &v) != 0 || v != 3600);
    FAIL_IF(ParseTimeStringU64("1d", &v) != 0 || v != 86400ULL);
    FAIL_IF(ParseTimeStringU64("1 day", &v) != 0 || v != 86400ULL);
    FAIL_IF(ParseTimeStringU64("1w", &v) != 0 || v != 604800ULL);
    FAIL_IF(ParseTimeStringU64("1 week", &v) != 0 || v != 604800ULL);
    FAIL_IF(ParseTimeStringU64("1y", &v) != 0 || v != 31536000ULL);
    FAIL_IF(ParseTimeStringU64("1 year", &v) != 0 || v != 31536000ULL);
    FAIL_IF(ParseTimeStringU64("  5  m  ", &v) != 0 || v != 300ULL);
    PASS;
}

static int UtilMiscParseTimeStringInvalidUnit(void)
{
    uint64_t v;
    FAIL_IF(ParseTimeStringU64("10q", &v) == 0);
    PASS;
}

static int UtilMiscParseTimeStringExactMax(void)
{
    uint64_t v;
    char buf[64];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)UINT64_MAX);
    FAIL_IF(ParseTimeStringU64(buf, &v) != 0 || v != UINT64_MAX);
    PASS;
}

static int UtilMiscParseTimeStringOverflowYears(void)
{
    uint64_t v;
    char buf[128];
    snprintf(buf, sizeof(buf), "%lluY", (unsigned long long)(UINT64_MAX / 31536000ULL + 1ULL));
    FAIL_IF(ParseTimeStringU64(buf, &v) != -1);
    PASS;
}

static int UtilMiscParseTimeStringOverflowDigits(void)
{
    uint64_t v;
    /* UINT64_MAX *10 */
    FAIL_IF(ParseTimeStringU64("184467440737095516160", &v) != -1);
    PASS;
}

static int UtilMiscParseTimeStringMalformed(void)
{
    uint64_t v;
    FAIL_IF(ParseTimeStringU64("", &v) == 0);
    FAIL_IF(ParseTimeStringU64("  ", &v) == 0);
    FAIL_IF(ParseTimeStringU64("abc", &v) == 0);
    FAIL_IF(ParseTimeStringU64("10ss", &v) == 0);
    PASS;
}

static int UtilMiscParseTimeStringTest03(void)
{
    uint64_t v;
    /* plus sign */
    FAIL_IF(ParseTimeStringU64("+5m", &v) != 0 || v != 300ULL);
    /* uppercase units */
    FAIL_IF(ParseTimeStringU64("2H", &v) != 0 || v != 7200ULL);
    FAIL_IF(ParseTimeStringU64("3DAYS", &v) != 0 || v != 3ULL * 86400ULL);
    /* boundary: largest value that doesn't overflow with seconds (UINT64_MAX) truncated by overflow
     * check */
    FAIL_IF(ParseTimeStringU64("0", &v) != 0 || v != 0ULL);
    /* near overflow valid case: (UINT64_MAX / 60) minutes becomes seconds <= UINT64_MAX */
    unsigned long long maxmins = (unsigned long long)(UINT64_MAX / 60ULL);
    char buf[64];
    snprintf(buf, sizeof(buf), "%llum", maxmins);
    FAIL_IF(ParseTimeStringU64(buf, &v) != 0 || v != (uint64_t)maxmins * 60ULL);
    /* overflow minutes */
    snprintf(buf, sizeof(buf), "%lluM", maxmins + 1ULL);
    FAIL_IF(ParseTimeStringU64(buf, &v) == 0);
    /* disallowed ms */
    FAIL_IF(ParseTimeStringU64("10ms", &v) == 0);
    PASS;
}

void UtilMiscRegisterTests(void)
{
    UtRegisterTest("UtilMiscParseSizeStringTest01",
                   UtilMiscParseSizeStringTest01);
    UtRegisterTest("UtilMiscParseSizeStringTest02", UtilMiscParseSizeStringTest02);
    UtRegisterTest("UtilMiscParseTimeStringTest01", UtilMiscParseTimeStringTest01);
    UtRegisterTest("UtilMiscParseTimeStringInvalidUnit", UtilMiscParseTimeStringInvalidUnit);
    UtRegisterTest("UtilMiscParseTimeStringExactMax", UtilMiscParseTimeStringExactMax);
    UtRegisterTest("UtilMiscParseTimeStringOverflowYears", UtilMiscParseTimeStringOverflowYears);
    UtRegisterTest("UtilMiscParseTimeStringOverflowDigits", UtilMiscParseTimeStringOverflowDigits);
    UtRegisterTest("UtilMiscParseTimeStringMalformed", UtilMiscParseTimeStringMalformed);
    UtRegisterTest("UtilMiscParseTimeStringTest03", UtilMiscParseTimeStringTest03);
}
#endif /* UNITTESTS */
