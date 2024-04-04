/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Get information on running host
 *
 */

#include "suricata-common.h"
#include "util-host-info.h"
#include "util-byte.h"
#include "util-debug.h"

#ifndef OS_WIN32
#include <sys/utsname.h>

#define VERSION_REGEX "^([0-9]+)\\.([0-9]+)"

int SCKernelVersionIsAtLeast(int major, int minor)
{
    struct utsname kuname;
    pcre2_code *version_regex;
    pcre2_match_data *version_regex_match;
    int en;
    int opts = 0;
    PCRE2_SIZE eo;
    int ret;
    int kmajor, kminor;

    /* get local version */
    if (uname(&kuname) != 0) {
        SCLogError("Invalid uname return: %s", strerror(errno));
        return 0;
    }

    SCLogDebug("Kernel release is '%s'", kuname.release);

    version_regex =
            pcre2_compile((PCRE2_SPTR8)VERSION_REGEX, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (version_regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError("pcre2 compile of \"%s\" failed at "
                   "offset %d: %s",
                VERSION_REGEX, (int)eo, errbuffer);
        goto error;
    }
    version_regex_match = pcre2_match_data_create_from_pattern(version_regex, NULL);

    ret = pcre2_match(version_regex, (PCRE2_SPTR8)kuname.release, strlen(kuname.release), 0, 0,
            version_regex_match, NULL);

    if (ret < 0) {
        SCLogError("Version did not cut");
        goto error;
    }

    if (ret < 3) {
        SCLogError("Version major and minor not found (ret %d)", ret);
        goto error;
    }

    char majorstr[32];
    size_t pcre2len = sizeof(majorstr);
    ret = pcre2_substring_copy_bynumber(
            version_regex_match, 1, (PCRE2_UCHAR8 *)majorstr, &pcre2len);
    if (ret < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        goto error;
    }

    char minorstr[32];
    pcre2len = sizeof(majorstr);
    ret = pcre2_substring_copy_bynumber(
            version_regex_match, 2, (PCRE2_UCHAR8 *)minorstr, &pcre2len);
    if (ret < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        goto error;
    }

    if (StringParseInt32(&kmajor, 10, 0, (const char *)majorstr) < 0) {
        SCLogError("Invalid value for kmajor: '%s'", minorstr);
        goto error;
    }
    if (StringParseInt32(&kminor, 10, 0, (const char *)minorstr) < 0) {
        SCLogError("Invalid value for kminor: '%s'", minorstr);
        goto error;
    }

    pcre2_match_data_free(version_regex_match);
    pcre2_code_free(version_regex);

    if (kmajor > major)
        return 1;
    if (kmajor == major && kminor >= minor)
        return 1;
error:
    return 0;
}

#else /* OS_WIN32 */

int SCKernelVersionIsAtLeast(int major, int minor)
{
    SCLogError("OS compare is not supported on Windows");
    return 0;
}

#endif /* OS_WIN32 */
