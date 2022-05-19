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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 *
 * IP addresses related utility functions
 */

#include "suricata-common.h"
#include "util-ip.h"
#include "util-byte.h"

/** \brief determine if a string is a valid ipv4 address
 *  \retval bool is addr valid?
 */
bool IPv4AddressStringIsValid(const char *str)
{
    int alen = 0;
    char addr[4][4];
    int dots = 0;

    memset(&addr, 0, sizeof(addr));

    uint32_t len = strlen(str);
    uint32_t i = 0;
    for (i = 0; i < len; i++) {
        if (!(str[i] == '.' || isdigit(str[i]))) {
            return false;
        }
        if (str[i] == '.') {
            if (dots == 3) {
                SCLogDebug("too many dots");
                return false;
            }
            addr[dots][alen] = '\0';
            dots++;
            alen = 0;
        } else {
            if (alen >= 3) {
                SCLogDebug("too long");
                return false;
            }
            addr[dots][alen++] = str[i];
        }
    }
    if (dots != 3)
        return false;

    addr[dots][alen] = '\0';
    for (int x = 0; x < 4; x++) {
        uint8_t a;
        if (StringParseUint8(&a, 10, 0, (const char *)addr[x]) < 0) {
            SCLogDebug("invalid value for address byte: %s", addr[x]);
            return false;
        }
    }
    return true;
}

/** \brief determine if a string is a valid ipv6 address
 *  \retval bool is addr valid?
 */
bool IPv6AddressStringIsValid(const char *str)
{
    int block_size = 0;
    int sep = 0;
    bool colon_seen = false;

    uint32_t len = strlen(str);
    uint32_t i = 0;
    for (i = 0; i < len && str[i] != 0; i++) {
        if (!(str[i] == '.' || str[i] == ':' ||
            isxdigit(str[i])))
            return false;

        if (str[i] == ':') {
            block_size = 0;
            colon_seen = true;
            sep++;
        } else if (str[i] == '.') {
            block_size = false;
            sep++;
        } else {
            if (block_size == 4)
                return false;
            block_size++;
        }
    }

    if (!colon_seen)
        return false;
    if (sep > 7) {
        SCLogDebug("too many seps %d", sep);
        return false;
    }
    return true;
}

/**
 * \brief Culls the non-netmask portion of the IP address. For example an IP
 *        address 192.168.240.1 would be chopped to 192.168.224.0 against a
 *        netmask value of 19.
 *
 * \param stream  Pointer the IP address that has to be masked
 * \param netmask The netmask value (cidr) to which the IP address has to be culled
 * \param key_bitlen  The bitlen of the stream
 */
void MaskIPNetblock(uint8_t *stream, int netmask, int key_bitlen)
{
    uint32_t mask = 0;
    int i = 0;
    int bytes = key_bitlen / 8;

    for (i = 0; i < bytes; i++) {
        mask = UINT_MAX;
        if ( ((i + 1) * 8) > netmask) {
            if ( ((i + 1) * 8 - netmask) < 8)
                mask = UINT_MAX << ((i + 1) * 8 - netmask);
            else
                mask = 0;
        }
        stream[i] &= mask;
    }

    return;
}
