/* Copyright (C) 2007-2013 Open Information Security Foundation
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
    uint8_t flags:3;
    uint8_t metric:5;
    uint8_t pad0;
    uint16_t cnt_match;                 /**< number of times this tag was reset/updated */

    uint32_t count;                     /**< count setting from rule */
    uint32_t sid;                       /**< sid originating the tag */
    uint32_t gid;                       /**< gid originating the tag */
    union {
        uint32_t packets;               /**< number of packets (metric packets) */
        uint32_t bytes;                 /**< number of bytes (metric bytes) */
    };
    uint32_t first_ts;                  /**< First time seen (for metric = seconds) */
    uint32_t last_ts;                   /**< Last time seen (to prune old sessions) */
#if __WORDSIZE == 64
    uint32_t pad1;
#endif
    struct DetectTagDataEntry_ *next;   /**< Pointer to the next tag of this
                                         *   session/src_host/dst_host (if any from other rule) */
} DetectTagDataEntry;

#define TAG_ENTRY_FLAG_DIR_SRC          0x01
#define TAG_ENTRY_FLAG_DIR_DST          0x02
#define TAG_ENTRY_FLAG_SKIPPED_FIRST    0x04

/* prototypes */
void DetectTagRegister(void);
void DetectTagDataFree(void *ptr);
void DetectTagDataListFree(void *ptr);

#endif /* __DETECT_TAG_H__ */

