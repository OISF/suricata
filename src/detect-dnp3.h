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

/**
 * Struct for mapping symbolic names to values.
 */
typedef struct DNP3Mapping_ {
    char     *name;
    uint16_t  value;
} DNP3Mapping;

/**
 * The type of detection to be performed.
 */
typedef enum DetectDNP3Type_ {
    DNP3_DETECT_TYPE_FC,
    DNP3_DETECT_TYPE_IND,
    DNP3_DETECT_TYPE_OBJ,
} DetectDNP3Type;

/**
 * The detection struct.
 */
typedef struct DetectDNP3_ {

    /* Type of detection. */
    int      detect_type;   /*<< Type of detection. */

    /* Function code for function code detection. */
    uint8_t  function_code;

    /* Internal indicator flags for IIN detection. */
    uint16_t ind_flags;

    /* Object info for object detection. */
    uint8_t  obj_group;
    uint8_t  obj_variation;
} DetectDNP3;

/* Map of internal indicators to value for external use. */
extern DNP3Mapping DNP3IndicatorsMap[];

void DetectDNP3FuncRegister(void);
void DetectDNP3IndRegister(void);
void DetectDNP3ObjRegister(void);
void DetectDNP3DataRegister(void);

#endif /* __DETECT_DNP3_H__ */
