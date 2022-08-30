/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_PCRE_H__
#define __DETECT_PCRE_H__

#include "detect-parse.h"

#define DETECT_PCRE_RELATIVE            0x00001
#define DETECT_PCRE_RAWBYTES            0x00002
#define DETECT_PCRE_CASELESS            0x00004

#define DETECT_PCRE_MATCH_LIMIT         0x00020
#define DETECT_PCRE_RELATIVE_NEXT       0x00040
#define DETECT_PCRE_NEGATE              0x00080

#define DETECT_PCRE_CAPTURE_MAX         8

#define SC_MATCH_LIMIT_DEFAULT           3500
#define SC_MATCH_LIMIT_RECURSION_DEFAULT 1500

typedef struct DetectPcreData_ {
    /* pcre options */
    DetectParseRegex parse_regex;

    int opts;
    uint16_t flags;
    uint8_t idx;
    uint8_t captypes[DETECT_PCRE_CAPTURE_MAX];
    uint32_t capids[DETECT_PCRE_CAPTURE_MAX];
    int thread_ctx_id;
} DetectPcreData;

/* prototypes */

int DetectPcrePayloadMatch(DetectEngineThreadCtx *,
        const Signature *, const SigMatchData *,
        Packet *, Flow *, const uint8_t *, uint32_t);

void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

