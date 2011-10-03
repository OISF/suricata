/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_TAG_H__
#define __DETECT_TAG_H__

#include "suricata-common.h"
#include "suricata.h"
#include "util-time.h"

/* Limit the number of times a session can be tagged by the
 * same rule without finishing older tags */
#define DETECT_TAG_MATCH_LIMIT 10

/* Limit the number of tags that a session can have */
#define DETECT_TAG_MAX_TAGS 50

/* Limit the number of pkts to capture. Change this to
 * zero to make it unlimited
 * TODO: load it from config (var tagged_packet_limit) */
#define DETECT_TAG_MAX_PKTS 256

/* Type of tag: session or host */
enum {
    DETECT_TAG_TYPE_SESSION,
    DETECT_TAG_TYPE_HOST,
    DETECT_TAG_TYPE_MAX
};

enum {
    DETECT_TAG_DIR_SRC,
    DETECT_TAG_DIR_DST,
    DETECT_TAG_DIR_MAX
};

enum {
    DETECT_TAG_METRIC_PACKET,
    DETECT_TAG_METRIC_SECONDS,
    DETECT_TAG_METRIC_BYTES,
    DETECT_TAG_METRIC_MAX
};

/** This will be the rule options/parameters */
typedef struct DetectTagData_ {
    uint8_t type;          /**< tag type */
    uint8_t direction;     /**< host direction */
    uint32_t count;        /**< count */
    uint32_t metric;       /**< metric */
} DetectTagData;

/** This is the installed data at the session/global or host table */
typedef struct DetectTagDataEntry_ {
    DetectTagData *td;                  /**< Pointer referencing the tag parameters */
    uint32_t sid;                       /**< sid originating the tag */
    uint32_t gid;                       /**< gid originating the tag */
    uint32_t packets;                   /**< number of packets */
    uint32_t bytes;                     /**< number of bytes */
    struct timeval first_ts;            /**< First time seen (for metric = seconds) */
    struct timeval last_ts;             /**< Last time seen (to prune old sessions) */
    struct DetectTagDataEntry_ *next;   /**< Pointer to the next tag of this
                                         * session/src_host/dst_host (if any from other rule) */
    uint16_t cnt_match;                 /**< number of times this tag was reset/updated */
    uint8_t skipped_first;              /**< Used for output. The first packet write the
                                             header with the data of the sig. The next packets use
                                             gid/sid/rev of the tagging engine */
} DetectTagDataEntry;

typedef struct DetectTagDataEntryList_ {
    DetectTagDataEntry *header_entry;
    Address addr;                       /**< Var used to store dst or src addr */
    uint8_t ipv;                        /**< IP Version */
} DetectTagDataEntryList;

/* prototypes */
void DetectTagRegister (void);
void DetectTagDataFree(void *ptr);
void DetectTagDataEntryFree(void *ptr);
void DetectTagDataListFree(void *ptr);
DetectTagDataEntry *DetectTagDataCopy(DetectTagDataEntry *dtd);

#endif /* __DETECT_TAG_H__ */

