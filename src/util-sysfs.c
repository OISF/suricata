/* Copyright (C) 2011-2022 Open Information Security Foundation
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
 * \author Richard McConnell <richard_mcconnell@rapid7.com>
 *
 * Sysfs utility file
 */

#include "util-sysfs.h"

#define SYSFS_MAX_FILENAME_LEN (SYSFS_MAX_FILENAME_SIZE + 5)

TmEcode SysFsWriteValue(const char *path, int64_t value)
{
#if defined(__linux__)
    struct stat stats;
    char fname[SYSFS_MAX_FILENAME_LEN] = "/sys/";

    if (!path || strlen(path) > SYSFS_MAX_FILENAME_SIZE) {
        SCLogWarning(SC_ERR_ARG_LEN_LONG, "File path too long, max allowed: %d",
                SYSFS_MAX_FILENAME_SIZE);
        SCReturnInt(TM_ECODE_FAILED);
    }

    strlcat(fname, path, sizeof(fname));

    if (stat(fname, &stats) != 0) {
        SCLogError(SC_ERR_FOPEN, "Could not gather stats for: %s", fname);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (S_ISREG(stats.st_mode) == 0) {
        SCLogError(SC_ERR_FOPEN, "File: %s is not a regular file", fname);
        SCReturnInt(TM_ECODE_FAILED);
    }

    FILE *fp = fopen(fname, "w");
    if (fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "Could not open file: %s", fname);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (fprintf(fp, "%ld", value) < 0) {
        SCLogError(SC_ERR_FWRITE, "Could not write to file: %s", fname);
        fclose(fp);
        SCReturnInt(TM_ECODE_FAILED);
    }
    fclose(fp);
#endif /* __LINUX__ */

    SCReturnInt(TM_ECODE_OK);
}
