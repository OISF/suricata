/* Copyright (C) 2020 Open Information Security Foundation
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
 * Utilities to work with xor encrypted data. This implementation is stored in
 * its own file for future expansion and optimizations.
 */

#include "util-xor.h"

/**
 * \brief Decodes a xor-encoded byte buffer into a byte buffer
 *
 * \param dest Destination byte buffer.
 * \param src Source byte buffer.
 * \param len Length of bytes to decode.
 * \param key Xor key to use.
 * \param key_len Length of xor key.
 *
 * \note src and dest buffers must contain at least len bytes, key_len must be
 *       greater than 0.
 */
void DecodeXor(uint8_t *dest, const uint8_t *src, const size_t len,
        const uint8_t *key, const size_t key_len)
{
    for (size_t i = 0; i < len; i++) {
        dest[i] = src[i] ^ key[i % key_len];
    }
}

/* UNITTESTS */
#ifdef UNITTESTS

#include "util-unittest.h"

static int DecodeXorTest(void)
{
    uint8_t src[] = {0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c};
    uint8_t dest[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t key[] = {0xb2, 0x25, 0x9a};
    uint8_t expected[] = {0x7c, 0x22, 0x4e, 0xf5, 0x78, 0xcb, 0xf8, 0x69};

    size_t len = sizeof(src) / sizeof(*src);
    size_t key_len = sizeof(key) / sizeof(*key);

    DecodeXor(dest, src, len, key, key_len);

    FAIL_IF(0 != memcmp(dest, expected, len));

    PASS;
}

void XorRegisterTests(void)
{
    UtRegisterTest("DecodeXorTest", DecodeXorTest);
}

#endif /* UNITTESTS */
