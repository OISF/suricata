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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 */

#ifndef __DETECT_GEOIP_H__
#define __DETECT_GEOIP_H__

#ifdef HAVE_GEOIP

#include <GeoIP.h>
#include "util-spm-bm.h"

#define GEOOPTION_MAXSIZE 64
#define GEOOPTION_MAXLOCATIONS 64

typedef struct DetectGeoipData_ {
    uint8_t location[GEOOPTION_MAXSIZE][GEOOPTION_MAXSIZE];  /** country code for now, null term.*/
    int nlocations; /** number of location strings parsed */
    uint32_t flags;
    GeoIP *geoengine;
} DetectGeoipData;

#endif

void DetectGeoipRegister(void);

#endif
