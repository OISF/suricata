/* Copyright (C) 2022 Open Information Security Foundation
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

#ifndef __DETECT_DNP3_H__
#define __DETECT_DNP3_H__

/**
 * Struct for mapping symbolic names to values.
 */
typedef struct DNP3Mapping_ {
    const char     *name;
    uint16_t  value;
} DNP3Mapping;

/* Map of internal indicators to value for external use. */
extern DNP3Mapping DNP3IndicatorsMap[];

void DetectDNP3Register(void);

#endif /* __DETECT_DNP3_H__ */
