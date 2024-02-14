/* Copyright (C) 2012-2019 Open Information Security Foundation
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
 * \author Bill Meeks <billmeeks8@gmail.com>
 */

#ifndef __DETECT_GEOIP_H__
#define __DETECT_GEOIP_H__

#ifdef HAVE_GEOIP

#include <maxminddb.h>

#define GEOOPTION_MAXSIZE 3 /* Country Code (2 chars) + NULL */
#define GEOOPTION_MAXLOCATIONS 64

typedef struct DetectGeoipData_ {
    uint8_t location[GEOOPTION_MAXLOCATIONS][GEOOPTION_MAXSIZE];  /** country code for now, null term.*/
    int nlocations;  /** number of location strings parsed */
    uint32_t flags;
    int mmdb_status; /** Status of DB open call, MMDB_SUCCESS or error */
    MMDB_s mmdb;     /** MaxMind DB file handle structure */
} DetectGeoipData;

#endif

void DetectGeoipRegister(void);

#endif
