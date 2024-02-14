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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef __UTIL_SPM_BS2BM__
#define __UTIL_SPM_BS2BM__

#include "suricata-common.h"

#define ALPHABET_SIZE 256

void Bs2BmBadchars(const uint8_t *, uint16_t, uint8_t *);
void Bs2BmBadcharsNocase(const uint8_t *, uint16_t, uint8_t *);
uint8_t *Bs2Bm(const uint8_t *, uint32_t, const uint8_t *, uint16_t, const uint8_t[]);
uint8_t *Bs2BmNocase(const uint8_t *, uint32_t, const uint8_t *, uint16_t, const uint8_t[]);

#endif /* __UTIL_SPM_BS2BM__ */

