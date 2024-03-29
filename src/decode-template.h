/* Copyright (C) 2015-2018 Open Information Security Foundation
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
 * \author XXX
 *
 */

#ifndef SURICATA_DECODE_TEMPLATE_H
#define SURICATA_DECODE_TEMPLATE_H

/* Header layout. Keep things like alignment and endianness in
 * mind while constructing this. */

typedef struct TemplateHdr_ {
    uint8_t proto;
    uint8_t pad0;
    uint16_t pad1;
} __attribute__((__packed__)) TemplateHdr;

#endif /* SURICATA_DECODE_TEMPLATE_H */
