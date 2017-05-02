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
#include "config.h"
#include "util-host-info.h"

#ifndef OS_WIN32
#include <sys/utsname.h>

#define VERSION_REGEX "^([0-9]+)\\.([0-9]+)"

int SCKernelVersionIsAtLeast(int major, int minor)
{
    struct utsname kuname;
    pcre *version_regex;
    pcre_extra *version_regex_study;
    const char *eb;
    int opts = 0;
    int eo;
#define MAX_SUBSTRINGS 3 * 6
    int ov[MAX_SUBSTRINGS];
    int ret;
    int kmajor, kminor;
    const char **list;

    /* get local version */
    if (uname(&kuname) != 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid uname return: %s",
                   strerror(errno));
        return 0;
    }

    SCLogDebug("Kernel release is '%s'", kuname.release);

    version_regex = pcre_compile(VERSION_REGEX, opts, &eb, &eo, NULL);
    if (version_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", VERSION_REGEX, eo, eb);
        goto error;
    }

    version_regex_study = pcre_study(version_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    ret = pcre_exec(version_regex, version_regex_study, kuname.release,
                    strlen(kuname.release), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "Version did not cut");
        goto error;
    }

    if (ret < 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "Version major and minor not found (ret %d)", ret);
        goto error;
    }

    pcre_get_substring_list(kuname.release, ov, ret, &list);

    kmajor = atoi(list[1]);
    kminor = atoi(list[2]);

    pcre_free_substring_list(list);
    pcre_free_study(version_regex_study);
    pcre_free(version_regex);

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
    SCLogError(SC_ERR_NOT_SUPPORTED, "OS compare is not supported on Windows");
    return 0;
}

#endif /* OS_WIN32 */
