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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_PCRE_H__
#define __DETECT_PCRE_H__

#define DETECT_PCRE_RELATIVE            0x00001
#define DETECT_PCRE_RAWBYTES            0x00002
#define DETECT_PCRE_URI                 0x00004

#define DETECT_PCRE_CAPTURE_PKT         0x00008
#define DETECT_PCRE_CAPTURE_FLOW        0x00010
#define DETECT_PCRE_MATCH_LIMIT         0x00020

#define DETECT_PCRE_HTTP_CLIENT_BODY    0x00040
#define DETECT_PCRE_HTTP_SERVER_BODY    0x00080

#define DETECT_PCRE_RELATIVE_NEXT       0x00100

/* new modifiers 2.8.5.3 support */
#define DETECT_PCRE_HEADER              0x00200
#define DETECT_PCRE_RAW_HEADER          0x00400
#define DETECT_PCRE_COOKIE              0x00800
#define DETECT_PCRE_METHOD              0x01000
#define DETECT_PCRE_HTTP_RAW_URI        0x02000
#define DETECT_PCRE_HTTP_STAT_MSG       0x04000
#define DETECT_PCRE_HTTP_STAT_CODE      0x08000
#define DETECT_PCRE_HTTP_USER_AGENT     0x10000
#define DETECT_PCRE_HTTP_HOST           0x20000
#define DETECT_PCRE_HTTP_RAW_HOST       0x40000

#define DETECT_PCRE_NEGATE              0x80000
#define DETECT_PCRE_CASELESS           0x100000

#define DETECT_PCRE_DNS_QUERY          0x200000

typedef struct DetectPcreData_ {
    /* pcre options */
    pcre *re;
    pcre_extra *sd;
    int opts;
    uint32_t flags;
    uint16_t capidx;
    char *capname;
} DetectPcreData;

/* prototypes */
int DetectPcrePayloadMatch(DetectEngineThreadCtx *, Signature *, SigMatch *, Packet *, Flow *, uint8_t *, uint32_t);
int DetectPcrePacketPayloadMatch(DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectPcrePayloadDoMatch(DetectEngineThreadCtx *, Signature *, SigMatch *,
                             Packet *, uint8_t *, uint16_t);
void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

