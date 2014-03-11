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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Utility function for seeding rand
 */

#include "suricata-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

/**
 * \brief create a seed number to pass to rand() , rand_r(), and similars
 * \retval seed for rand()
 */
unsigned int RandomTimePreseed(void)
{
    /* preseed rand() */
    time_t now = time ( 0 );
    unsigned char *p = (unsigned char *)&now;
    unsigned seed = 0;
    size_t ind;

    for ( ind = 0; ind < sizeof now; ind++ )
      seed = seed * ( UCHAR_MAX + 2U ) + p[ind];

    return seed;
}

