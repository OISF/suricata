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

#ifndef __UTIL_XOR_H__
#define __UTIL_XOR_H__

#include "suricata-common.h"

void DecodeXor(uint8_t *dest, const uint8_t *src, const size_t len,
        const uint8_t *key, const size_t key_len);

#ifdef UNITTESTS

void XorRegisterTests(void);

#endif /* UNITTESTS */

#endif /* __UTIL_XOR_H__ */

