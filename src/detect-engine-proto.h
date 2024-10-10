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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_PROTO_H
#define SURICATA_DETECT_PROTO_H

// clang-format off
#define DETECT_PROTO_ANY               BIT_U8(0) /**< Indicate that given protocol is considered as IP */
#define DETECT_PROTO_ONLY_PKT          BIT_U8(1) /**< Indicate that we only care about packet payloads. */
#define DETECT_PROTO_ONLY_STREAM       BIT_U8(2) /**< Indicate that we only care about stream payloads. */
#define DETECT_PROTO_IPV4              BIT_U8(3) /**< IPv4 only */
#define DETECT_PROTO_IPV6              BIT_U8(4) /**< IPv6 only */
// clang-format on

typedef struct DetectProto_ {
    uint8_t proto[256/8]; /**< bit array for 256 protocol bits */
    uint8_t flags;
} DetectProto;

/* prototypes */
int DetectProtoParse(DetectProto *dp, const char *str);
int DetectProtoContainsProto(const DetectProto *, int);

void DetectProtoTests(void);

#endif /* SURICATA_DETECT_PROTO_H */
