/* Copyright (C) 2011-2012 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __UTIL_CHECKSUM_H__
#define __UTIL_CHECKSUM_H__

#include "decode.h"

int ReCalculateChecksum(Packet *p);
int ChecksumAutoModeCheck(uint64_t thread_count,
        uint64_t iface_count, uint64_t iface_fail);

/* constant linked with detection of interface with
 * invalid checksums */
#define CHECKSUM_SAMPLE_COUNT 1000ULL
#define CHECKSUM_INVALID_RATIO 10

#endif
