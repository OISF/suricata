/* Copyright (C) 2012 BAE Systems
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#include "util-pescan.h"
#include "libpescan.h"
#include "conf.h"

/* Constants */
#define WAIT_SCAN_BYTES     32768 /* Wait for 32K bytes before running pescan */
#define MIN_SCAN_BYTES         62 /* Minimum for finding 'PE' string */
#define PREF_SCAN_BYTES       512 /* Preferred number of bytes to scan */
#define MAX_SCAN_BYTES      65536 /* 64K for now */

static PEScanConfig pescan_config = { 0, 0, 0 };

/**
 * \brief Gets the max number of bytes to allocate for scanning a file
 *
 * \param file Optional file parameter (for file size)
 * \return The max number of bytes to scan from a file
 */
uint32_t PEScanGetMaxBytes(File *file) {
    uint32_t maxSize = MAX_SCAN_BYTES;

    /* First get from config file */
    PEScanConfig *pecfg = PEScanGetConfig();
    if ((pecfg != NULL) && (pecfg->max_scan_bytes > 0)) {
        maxSize = pecfg->max_scan_bytes;
    }

    /* Only use file size if specified and within valid range */
    if ((file != NULL) && (file->size >= MIN_SCAN_BYTES) && (file->size < maxSize)) {
        maxSize = file->size;
    }

    return maxSize;
}

/**
 * \brief Gets the pescan config settings
 *
 * \return Pointer to the config settings
 */
PEScanConfig * PEScanGetConfig() {

    int ret;
    intmax_t val;

    /* If uninitialized, then initialize */
    if (pescan_config.pref_scan_bytes == 0) {

        /* First set defaults */
        pescan_config.max_scan_bytes = MAX_SCAN_BYTES;
        pescan_config.pref_scan_bytes = PREF_SCAN_BYTES;
        pescan_config.wait_scan_bytes = WAIT_SCAN_BYTES;

        /* Now update based on config file */
        ConfNode *config = ConfGetNode("file-pescan");
        if (config != NULL) {

            ret = ConfGetChildValueInt(config, "max-scan-bytes", &val);
            if (ret) {
                pescan_config.max_scan_bytes = val;
            }

            ret = ConfGetChildValueInt(config, "pref-scan-bytes", &val);
            if (ret) {
                pescan_config.pref_scan_bytes = val;
            }

            ret = ConfGetChildValueInt(config, "wait-scan-bytes", &val);
            if (ret) {
                pescan_config.wait_scan_bytes = val;
            }
        }
    }

    return &pescan_config;
}

/**
 * \brief Makes a deep copy of a PE Attribs data structure
 *
 * Copies the PE header attributes into a newly allocated and populated structure.
 *
 * \param peattrib The structure to copy
 * \return The newly allocated and populated structure, otherwise NULL if the
 * operation fails
 */
peattrib_t * CopyPEAttribs(peattrib_t *peattrib) {

    peattrib_t *newpeattrib = NULL;

    if (peattrib != NULL) {
        newpeattrib = SCMalloc(sizeof(peattrib_t));
        if (unlikely(newpeattrib == NULL)) {
            goto error;
        }

        /* Now deep copy over elements (no pointers in data structure) */
        memcpy(newpeattrib, peattrib, sizeof(peattrib_t));
    }

    return newpeattrib;

error:
    return NULL;
}

/**
 * \brief Scans a file for PE meta data and anomaly detection
 *
 * \param file The file to scan (partially or complete)
 * \param scanbuf preallocated buffer for scanning PE files
 * \retval 0 Not a PE file or not enough data to scan
 * \retval non-0 Found a PE file and return the proper PE indicator result
 */
int PEScanFile(File *file, uint8_t *scanbuf) {

    uint8_t *data = NULL;
    uint32_t dlen = 0, bytes, maxSize;
    int ret = 0;
    peattrib_t peattrib;

    /* Always mark as scanned, even when file is too small to ensure that file
     * cleanup occurs in the logger */
    file->pescan_flags |= PEFILE_SCANNED;

    if (file->chunks_head == NULL) {
        SCLogDebug("File Checks Header is NULL");
        SCReturnInt(0);
    }
    if (file->size < MIN_SCAN_BYTES) {
        SCLogDebug("File size is smaller than %d bytes", MIN_SCAN_BYTES);
        SCReturnInt(0);
    }

    PEScanConfig *pecfg = PEScanGetConfig();
    maxSize = PEScanGetMaxBytes(file);
    SCLogDebug("Max size to scan: %d", maxSize);
    data = scanbuf;
    if (data == NULL) {
        /* Allocate scan buffer on the heap (only when not passed in) */
        SCLogDebug("Need to allocate memory locally");
        data = SCMalloc(maxSize);
        if (unlikely(data == NULL)) {
            goto error;
        }
    }
    memset(data, 0x00, maxSize);

    /* Now scan the minimal amount of chunks until we get a PE determination */
    FileData *ffd;
    for (ffd = file->chunks_head; ffd != NULL; ffd = ffd->next) {
        SCLogDebug("ffd %p", ffd);

        /* Make sure number of bytes copied never exceeds the max allowed */
        bytes = ((ffd->len + dlen <= maxSize) ?
                ffd->len : maxSize - dlen);

        /* If no new bytes, then break out of loop */
        if (bytes == 0) {
            SCLogDebug("Already hit max bytes to scan, breaking out of loop");
            break;
        }

        memcpy(data + dlen, ffd->data, bytes);
        SCLogDebug("Bytes copied: %u", bytes);

        dlen += bytes;
        SCLogDebug("Total data size: %u", dlen);

        /* If minimum not met, continue on */
        if (dlen < MIN_SCAN_BYTES) {
            SCLogDebug("Minimum bytes not met, continuing to next chunk");
            continue;
        }

        if ((pecfg != NULL) && (dlen < pecfg->pref_scan_bytes) &&
                (ffd->next != NULL)) {
            SCLogDebug("Preferred bytes not met, continuing to next chunk");
            continue;
        }

        /* Now run the scanner utility */
        SCLogDebug("Bytes to scan: %u", dlen);

        /* Zeroize PE data structure */
        memset(&peattrib, 0x00, sizeof(peattrib_t));

        /* Run the scanner */
        ret = pescan(&peattrib, (unsigned char *) data, dlen, SCLogDebugEnabled());
        SCLogDebug("PEScan result: %d", ret);

        /* PE was found */
        if (ret != PE_NOT_PE && ret != PE_INDETERMINATE) {

            /* Save attribs structure by making a deep copy */
            file->peattrib = CopyPEAttribs(&peattrib);
            if (unlikely(file->peattrib == NULL)) {
                goto error;
            }

            /* Generate and save PE score */
            file->peattrib->pescore = pescore(file->peattrib);

            SCLogDebug("PE-Scanned File is a PE with a score of (%f)",
                    file->peattrib->pescore);

            /* If PE is truncated, we want to allow to run at least one more
             * time */
            if (ret == PE_TRUNCATED) {
                /* Log that a truncated PE was found */
                SCLogDebug("Truncated PE found of size: %lu..."
                        "re-scanning...", file->size);
                continue;
            } else {
                /* Otherwise we are done so break out of the loop */
                SCLogDebug("PE Scan completed");
                break;
            }
        } else if (ret == PE_INDETERMINATE) {
            /* Continue for more data */
            SCLogDebug("Not enough bytes to determine PE status...re-scanning...");
            continue;
        } else {
            /* Otherwise Not a PE so break */
            SCLogDebug("PE-Scanned File is not a PE");
            break;
        }
    }

    /* Check if minimum never met */
    if (dlen < MIN_SCAN_BYTES) {
        SCLogInfo("Size was expected to contain enough data (%ld), "
                "but not enough found (%u)", file->size, dlen);
    }

    /* Free data buffer (if allocated locally) */
    if (scanbuf == NULL) {
        SCFree(data);
    }

    /* Return with the ret flag */
    SCReturnInt(ret);

error:
    if (file->peattrib != NULL) {
        SCFree(file->peattrib);
    }
    file->peattrib = NULL;

    /* Free data buffer (if allocated locally) */
    if (scanbuf == NULL) {
        SCFree(data);
    }

    SCReturnInt(0);
}
