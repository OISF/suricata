/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 *
 * Implements cryptographic functions.
 * Based on the libtomcrypt library ( http://libtom.org/?page=features&newsitems=5&whatfile=crypt )
 */

#ifndef UTIL_CRYPT_H_
#define UTIL_CRYPT_H_

#include "suricata-common.h"

/* Ratio of output bytes to input bytes for Base64 Encoding is 4:3, hence the
 * required output bytes are 4 * ceil(input_len / 3) and an additional byte
 * for storing the NULL pointer.
 * */
#define BASE64_BUFFER_SIZE(x)  ((4 * ((x) + 2) / 3) + 1)

typedef enum {
    SC_BASE64_OK,
    SC_BASE64_INVALID_ARG,
    SC_BASE64_OVERFLOW,

} CryptId;

int Base64Encode(const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen);

#endif /* UTIL_CRYPT_H_ */
