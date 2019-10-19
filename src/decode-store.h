/* Copyright (C) 2007-2019 Open Information Security Foundation
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

#ifndef __DECODE_STORE_H__
#define __DECODE_STORE_H__

enum DecodeStoreTypes {
    DECODE_STORE_TYPE_VLAN,
    DECODE_STORE_TYPE_MPLS,
    DECODE_STORE_TYPE_TLV,   /**< generic TLV (type length value): [type 8 bits][len 8 bits][value ...] */
    DECODE_STORE_TYPE_NEXT,  /**< static storage full, switch to dynamic */
};

enum DecodeStoreTLVTypes {
    DECODE_STORE_TLV_TYPE_NOTSET,
    DECODE_STORE_TLV_TYPE_MAC,
};

void DecodeStoreAddVLAN(Packet *p, const uint16_t vlan_id);
void DecodeStoreAddMPLS(Packet *p, const uint32_t label);
int DecodeStoreAddTLV(Packet *p, uint8_t etype, const uint8_t *data, uint8_t data_len);

int DecodeStoreGetVLAN(const Packet *p, int n, uint16_t *vlan_id);
int DecodeStoreGetMPLS(const Packet *p, int n, uint32_t *label);
int DecodeStoreGetTLV(const Packet *p, int n, const uint8_t etype,
        uint8_t **data, uint8_t *data_len, const uint8_t data_size);

#endif /* __DECODE_STORE_H__ */
