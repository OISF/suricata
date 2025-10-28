/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef SURICATA_DETECT_THRESHOLD_H
#define SURICATA_DETECT_THRESHOLD_H

#define TYPE_LIMIT     1
#define TYPE_BOTH      2
#define TYPE_THRESHOLD 3
#define TYPE_DETECTION 4
#define TYPE_RATE      5
#define TYPE_SUPPRESS  6
#define TYPE_BACKOFF   7

#define TRACK_DST    1
#define TRACK_SRC    2
#define TRACK_RULE   3
#define TRACK_EITHER 4 /**< either src or dst: only used by suppress */
#define TRACK_BOTH   5 /* used by rate_filter to match detections by both src and dst addresses */
#define TRACK_FLOW   6 /**< track by flow */

/* Get the new action to take */
#define TH_ACTION_ALERT  0x01
#define TH_ACTION_DROP   0x02
#define TH_ACTION_PASS   0x04
#define TH_ACTION_LOG    0x08
#define TH_ACTION_SDROP  0x10
#define TH_ACTION_REJECT 0x20

/* distinct counting support (for detection_filter) */
#define DF_UNIQUE_NONE     0
#define DF_UNIQUE_SRC_PORT 1
#define DF_UNIQUE_DST_PORT 2

/**
 * \typedef DetectThresholdData
 * A typedef for DetectThresholdData_
 */

typedef struct DetectThresholdData_ {
    uint32_t count;      /**< Event count */
    uint32_t seconds;    /**< Event seconds */
    uint8_t type;        /**< Threshold type : limit , threshold, both, detection_filter */
    uint8_t track;       /**< Track type: by_src, by_dst */
    uint8_t new_action;  /**< new_action alert|drop|pass|log|sdrop|reject */
    uint32_t timeout;    /**< timeout */
    uint32_t flags;      /**< flags used to set option */
    uint32_t multiplier; /**< backoff multiplier */
    uint8_t unique_on;   /**< distinct counting on specific field (DF_UNIQUE_*) */
    DetectAddressHead addrs;
} DetectThresholdData;

/**
 * Registration function for threshold: keyword
 */

void DetectThresholdRegister(void);
DetectThresholdData *DetectThresholdDataCopy(DetectThresholdData *);

#endif /*SURICATA_DETECT_THRESHOLD_H */
