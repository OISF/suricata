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

#define DETECT_PCRE_RELATIVE      0x01
#define DETECT_PCRE_RAWBYTES      0x02
#define DETECT_PCRE_URI           0x04

#define DETECT_PCRE_CAPTURE_PKT   0x08
#define DETECT_PCRE_CAPTURE_FLOW  0x10
#define DETECT_PCRE_MATCH_LIMIT   0x20

#define DETECT_PCRE_HTTP_BODY_AL  0x40
#define DETECT_PCRE_RELATIVE_NEXT 0x80

typedef struct DetectPcreData_ {
    /* pcre options */
    pcre *re;
    pcre_extra *sd;
    int opts;

    uint8_t flags;
    uint8_t negate;

    char *capname;
    uint16_t capidx;
} DetectPcreData;

/* prototypes */
int DetectPcrePayloadMatch(DetectEngineThreadCtx *, Signature *, SigMatch *, Packet *, Flow *, uint8_t *, uint32_t);
int DetectPcrePacketPayloadMatch(DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
//int DetectPcrePayloadMatch(DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectPcrePayloadDoMatch(DetectEngineThreadCtx *, Signature *, SigMatch *,
                             Packet *, uint8_t *, uint16_t);
void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

