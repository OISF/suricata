/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

#ifndef SURICATA_FLOW_VAR_H
#define SURICATA_FLOW_VAR_H

#include "flow.h"
#include "util-var.h"

/** Available data types for Flowvars */

#define FLOWVAR_TYPE_STR 1
#define FLOWVAR_TYPE_INT 2
#define FLOWVAR_TYPE_FLOAT 3

typedef uint8_t FlowVarKeyLenType;
/** Struct used to hold the string data type for flowvars */
typedef struct FlowVarTypeStr {
    uint8_t *value;
    uint16_t value_len;
} FlowVarTypeStr;

/** Struct used to hold the integer data type for flowvars */
typedef struct FlowVarTypeInt_ {
    uint32_t value;
} FlowVarTypeInt;

/** Struct used to hold the integer data type for flowvars */
typedef struct FlowVarTypeFloat_ {
    double value;
} FlowVarTypeFloat;

/** Generic Flowvar Structure */
typedef struct FlowVar_ {
    uint16_t type; /* type, DETECT_FLOWVAR in this case */
    uint8_t datatype;
    FlowVarKeyLenType keylen;
    uint32_t idx;       /* name idx */
    GenericVar *next;   /* right now just implement this as a list,
                         * in the long run we have think of something
                         * faster. */
    union {
        FlowVarTypeStr fv_str;
        FlowVarTypeInt fv_int;
        FlowVarTypeFloat fv_float;
    } data;
    uint8_t *key;
} FlowVar;

/** Flowvar Interface API */

void FlowVarAddIdValue(Flow *, uint32_t id, uint8_t *value, uint16_t size);
void FlowVarAddKeyValue(
        Flow *f, uint8_t *key, FlowVarKeyLenType keylen, uint8_t *value, uint16_t size);

void FlowVarAddIntNoLock(Flow *, uint32_t, uint32_t);
void FlowVarAddInt(Flow *, uint32_t, uint32_t);
void FlowVarAddFloat(Flow *, uint32_t, double);
FlowVar *FlowVarGet(Flow *, uint32_t);
FlowVar *FlowVarGetByKey(Flow *f, const uint8_t *key, FlowVarKeyLenType keylen);
void FlowVarFree(FlowVar *);
void FlowVarPrint(GenericVar *);

#endif /* SURICATA_FLOW_VAR_H */
