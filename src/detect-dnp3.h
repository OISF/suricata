/* Copyright (C) 2015 Open Information Security Foundation
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

typedef enum DetectDNP3Type_ {
    DNP3_DETECT_FUNCTION_CODE,
    DNP3_DETECT_INTERNAL_INDICATOR,
} DetectDNP3Type;

typedef struct DetectDNP3_ {
    int type;
    uint8_t function_code;
    uint16_t ind_flags;
} DetectDNP3;

void DetectDNP3FuncRegister(void);
void DetectDNP3IndRegister(void);

#endif /* !__DETECT_DNP3_H__ */
