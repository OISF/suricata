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
#define MAX_FILE_NAME         256

static PEScanConfig pescan_config = { 0, 0, 0 };

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
 * \brief Scans a file for PE meta data and anomaly detection
 *
 * \param file The file to scan (partially or complete)
 * \retval 0 Not a PE file or not enough data to scan
 * \retval non-0 Found a PE file and return the proper PE indicator result
 */
int PEScanFile(File *file) {

    uint8_t data[MAX_SCAN_BYTES] = {0};
    char filename[MAX_FILE_NAME] = {0};
    uint32_t dlen = 0, bytes;
    int ret = 0, flen;
    peattrib_t *peattrib = NULL;

    /* Always mark as scanned, even when file is too small to ensure that file cleanup occurs in the logger */
    file->pescan_flags |= PEFILE_SCANNED;

    if (file->chunks_head == NULL) {
	SCLogDebug("File Checks Header is NULL");
	SCReturnInt(0);
    }
    if (file->size < MIN_SCAN_BYTES) {
	SCLogDebug("File size is smaller than %d bytes", MIN_SCAN_BYTES);
	SCReturnInt(0);
    }

    /* Now scan the minimal amount of chunks until we get a PE determination */
    FileData *ffd;
    for (ffd = file->chunks_head; ffd != NULL; ffd = ffd->next) {
	SCLogDebug("ffd %p", ffd);

	/* Make sure number of bytes copied never exceeds the max allowed */
	bytes = ((ffd->len + dlen <= MAX_SCAN_BYTES) ? ffd->len : MAX_SCAN_BYTES - dlen);

	/* If no new bytes, then break out of loop */
	if (bytes == 0) {
	    SCLogDebug("Already hit max bytes to scan, breaking out of loop");
	    break;
	}

	memcpy(data + dlen, ffd->data, bytes);
	SCLogDebug("Bytes copied: %u\n", bytes);

	dlen += bytes;
	SCLogDebug("Total data size: %u\n", dlen);

	/* If minimum not met, continue on */
	if (dlen < MIN_SCAN_BYTES) {
	    SCLogDebug("Minimum bytes not met, continuing to next chunk");
	    continue;
	}

	if (dlen < PEScanGetConfig()->pref_scan_bytes && ffd->next != NULL) {
	    SCLogDebug("Preferred bytes not met, continuing to next chunk");
	    continue;
	}

	/* Now run the scanner utility */
	SCLogDebug("Bytes to scan: %u\n", dlen);

	/* Init PE data structure (only once) */
	if (peattrib == NULL) {
	    peattrib = SCMalloc(sizeof(peattrib_t));
	    if (peattrib == NULL) {
		goto error;
	    }
	}
	memset(peattrib, 0x00, sizeof(peattrib_t));

	/* Run the scanner */
	ret = pescan(peattrib, (unsigned char *) data, dlen, SCLogDebugEnabled());
	SCLogDebug("PEScan result: %d\n", ret);

	/* If ret != 0, then PE was found */
	if (ret != PE_NOT_PE && ret != PE_INDETERMINATE) {

	    /* Save attribs structure */
	    file->peattrib = peattrib;

	    /* Generate and save PE score */
	    peattrib->pescore = pescore(peattrib);

	    /* Log that a PE was found */
	    flen = snprintf(filename, (file->name_len < MAX_FILE_NAME ? file->name_len + 1 : MAX_FILE_NAME), "%s", file->name);
	    if (flen > 0) {
		SCLogInfo("Found that file \"%s\" is a PE", filename);
	    }
	    else {
		SCLogInfo("Found PE with invalid filename");
	    }

	    /* If PE is truncated, we want to allow to run at least one more time */
	    if (ret == PE_TRUNCATED) {
		/* Log that a truncated PE was found */
		if (flen > 0) {
		    SCLogDebug("Truncated PE found: \"%s\" Size: %lu", filename, file->size);
		    SCLogDebug("Re-scanning...");
		}
	    }

	    /* Otherwise we are done so break out of the loop */
	    else {
		SCLogDebug("PE Scan completed");
		break;
	    }
	}

	/* Otherwise Not a PE so free the data structure */
	else {

	    if (SCLogDebugEnabled()) {
		flen = snprintf(filename, (file->name_len < MAX_FILE_NAME ? file->name_len + 1 : MAX_FILE_NAME), "%s", file->name);
		if (flen > 0) {
		    SCLogDebug("File \"%s\" is not a PE", filename);
		}
		else {
		    SCLogDebug("Found PE with invalid filename");
		}
	    }
	    SCFree(peattrib);
	    break;
	}
    }

    /* Check if minimum never met */
    if (dlen < MIN_SCAN_BYTES) {
	SCLogInfo("Size was expected to contain enough data (%ld), but not enough found (%u)\n", file->size, dlen);
    }

    /* Return with the ret flag */
    SCReturnInt(ret);

 error:
    if (peattrib != NULL) {
	SCFree(peattrib);
    }
    file->peattrib = NULL;
    SCReturnInt(0);
}
