/* Copyright (C) 2021 IPFire Development Team
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
 * \author Michael Tremer <michael.tremer@ipfire.org>
 *
 * Implements IPFire Location support (geoip keyword)
 */

#ifndef __DETECT_LOCATION_H__
#define __DETECT_LOCATION_H__

#ifdef HAVE_LIBLOC

#include <libloc/libloc.h>
#include <libloc/database.h>

enum location_flags {
    LOCATION_FLAG_SRC     = (1 << 0),
    LOCATION_FLAG_DST     = (1 << 1),
    LOCATION_FLAG_BOTH    = (1 << 2),
    LOCATION_FLAG_NEGATED = (1 << 3),
};

struct DetectLocationData {
    struct loc_ctx* ctx;
    struct loc_database* db;
    char** countries;
    int flags;
};

#endif /* HAVE_LIBLOC */

void DetectLocationRegister(void);

#endif /* __DETECT_LOCATION_H__ */
