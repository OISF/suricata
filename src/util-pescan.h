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

#ifndef __UTIL_PESCAN_H_
#define __UTIL_PESCAN_H_

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-pescan.h"
#include "util-debug.h"
#include "util-spm-bm.h"

/**
 * \brief Structure for containing configuration options
 *
 */
typedef struct PEScanConfig {

    uint32_t max_scan_bytes;  /**< Maximum file bytes to scan */
    uint32_t pref_scan_bytes;  /**< Preferrable amount of bytes to scan to achieve result */
    uint32_t wait_scan_bytes;  /**< Number of bytes to wait for before invoking pescan detector match function */

} PEScanConfig;

/* Function prototypes */
int PEScanFile(File *file);
PEScanConfig * PEScanGetConfig();

#endif
