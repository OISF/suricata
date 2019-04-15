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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 *
 * IP addresses related utility functions
 */

#include "suricata-common.h"
#include "util-ip.h"

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
        int a = atoi(addr[x]);
        if (a < 0 || a >= 256) {
            SCLogDebug("out of range");
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
 * \brief Validates an IPV4 address and returns the network endian arranged
 *        version of the IPV4 address
 *
 * \param addr Pointer to a character string containing an IPV4 address.  A
 *             valid IPV4 address is a character string containing a dotted
 *             format of "ddd.ddd.ddd.ddd"
 *
 * \retval Pointer to an in_addr instance containing the network endian format
 *         of the IPV4 address
 * \retval NULL if the IPV4 address is invalid
 */
struct in_addr *ValidateIPV4Address(const char *addr_str)
{
    struct in_addr *addr = NULL;

    if (!IPv4AddressStringIsValid(addr_str))
        return NULL;

    if ( (addr = SCMalloc(sizeof(struct in_addr))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in ValidateIPV4Address. Exiting...");
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET, addr_str, addr) <= 0) {
        SCFree(addr);
        return NULL;
    }

    return addr;
}

/**
 * \brief Validates an IPV6 address and returns the network endian arranged
 *        version of the IPV6 addresss
 *
 * \param addr Pointer to a character string containing an IPV6 address
 *
 * \retval Pointer to a in6_addr instance containing the network endian format
 *         of the IPV6 address
 * \retval NULL if the IPV6 address is invalid
 */
struct in6_addr *ValidateIPV6Address(const char *addr_str)
{
    struct in6_addr *addr = NULL;

    if (!IPv6AddressStringIsValid(addr_str))
        return NULL;

    if ( (addr = SCMalloc(sizeof(struct in6_addr))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in ValidateIPV6Address. Exiting...");
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET6, addr_str, addr) <= 0) {
        SCFree(addr);
        return NULL;
    }

    return addr;
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
