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

#ifndef __DETECT_PROTO_H__
#define __DETECT_PROTO_H__

#define DETECT_PROTO_ANY            0x01 /**< Indicate that given protocol
                                              is considered as IP */
#define DETECT_PROTO_ONLY_PKT       0x02 /**< Indicate that we only care
                                              about packet payloads. */
#define DETECT_PROTO_ONLY_STREAM    0x04 /**< Indicate that we only care
                                              about stream payloads. */

typedef struct DetectProto_ {
    uint8_t proto[256/8]; /**< bit array for 256 protocol bits */
    uint8_t flags;
} DetectProto;

/* prototypes */
int DetectProtoParse(DetectProto *dp, char *str);
int DetectProtoContainsProto(DetectProto *, int);

void DetectProtoTests(void);

#endif /* __DETECT_PROTO_H__ */

