/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

#ifndef __DECODE_VNTAG_H__
#define __DECODE_VNTAG_H__

/* https://www.ieee802.org/1/files/public/docs2009/new-pelissier-vntag-seminar-0508.pdf */
/** VNTag macros to access VNTag direction, dst vif_id, dest, looped, version, src vif_id **/
#define GET_VNTAG_DIR(vntagh)     ((SCNtohl((vntagh)->tag) & 0x80000000) >> 31)
#define GET_VNTAG_PTR(vntagh)     ((SCNtohl((vntagh)->tag) & 0x40000000) >> 30)
#define GET_VNTAG_DEST(vntagh)    ((SCNtohl((vntagh)->tag) & 0x3FFF0000) >> 16)
#define GET_VNTAG_LOOPED(vntagh)  ((SCNtohl((vntagh)->tag) & 0x00008000) >> 15)
#define GET_VNTAG_VERSION(vntagh) ((SCNtohl((vntagh)->tag) & 0x00003000) >> 12)
#define GET_VNTAG_SRC(vntagh)     ((SCNtohl((vntagh)->tag) & 0x00000FFF))
#define GET_VNTAG_PROTO(vntagh)   ((SCNtohs((vntagh)->protocol)))

/** VNTag header struct */
typedef struct VNTagHdr_ {
    uint32_t tag;
    uint16_t protocol; /**< protocol field */
} __attribute__((__packed__)) VNTagHdr;

/** VNTag header length */
#define VNTAG_HEADER_LEN 6

void DecodeVNTagRegisterTests(void);

#endif /* __DECODE_VNTAG_H__ */
