/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "util-conf.h"
#include "util-file.h"
#include "util-mimetype.h"
#include "rust.h"

#ifdef HAVE_MIMETYPE

#define FILE_MIMETYPE_MIN_SIZE 512

int FileMimetypeLookup(File *file)
{
    if (file == NULL || FileDataSize(file) == 0) {
        SCReturnInt(-1);
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint64_t offset = 0;

    StreamingBufferGetData(file->sb, &data, &data_len, &offset);
    if (offset == 0) {
        if (FileDataSize(file) >= FILE_MIMETYPE_MIN_SIZE) {
            file->mimetype = SCGetMimetype(data, data_len);
        } else if (file->state >= FILE_STATE_CLOSED) {
            file->mimetype = SCGetMimetype(data, data_len);
        }
    }
    SCReturnInt(0);
}

void FileMimetypeSetup(void)
{
#ifndef HAVE_GPL_MIMETYPE
    /* create MIME type directory environment variable early so that tree_magic_mini implicit
     * initialization can use it */
    const char *mimetype_dir;
    if (SCConfGet("mimetype-dir", &mimetype_dir) == 1) {
        /* only set the mimetype dir environment variable if it is set in the config */
        SCLogConfig("Using mimetype directory: %s", mimetype_dir);
        setenv("TREE_MAGIC_DIR", mimetype_dir, 0);
    } else {
        /* if not set, try to use default if available */
        const char *data_dir = ConfigGetDataDirectory();
        struct stat st;
        char mime_path[PATH_MAX];
        snprintf(mime_path, sizeof(mime_path), "%s/mimetype/", data_dir); // TODO WINDOWS
        if (stat(data_dir, &st) != 0) {
            SCLogConfig("Using mimetype information from system");
            return;
        }
        SCLogConfig("Using default mimetype directory: %s", mime_path);
        setenv("TREE_MAGIC_DIR", mime_path, 0);
    }
#else
    SCLogConfig("Using embedded mimetype information");
#endif /* not HAVE_GPL_MIMETYPE */
}

#endif /* HAVE_MIMETYPE */
