/** Copyright(c) 2009 Open Information Security Foundation.
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Flow level variable support for complex detection rules
 * Supported types atm are String and Integers
 */

#ifndef __FLOW_VAR_H__
#define __FLOW_VAR_H__

#include "flow.h"
#include "util-var.h"

/** Available data types for Flowvars */

#define FLOWVAR_TYPE_STR 1
#define FLOWVAR_TYPE_INT 2

/** Struct used to hold the string data type for flowvars */
typedef struct FlowVarTypeStr {
    uint8_t *value;
    uint16_t value_len;
}FlowVarTypeStr;

/** Struct used to hold the integer data type for flowvars */
typedef struct FlowVarTypeInt_ {
    uint32_t value;
}FlowVarTypeInt;

/** Generic Flowvar Structure */
typedef struct FlowVar_ {
    uint8_t type; /* type, DETECT_FLOWVAR in this case */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
    uint16_t idx; /* name idx */
    uint8_t datatype;
    union {
        FlowVarTypeStr fv_str;
        FlowVarTypeInt fv_int;
    } data;

} FlowVar;


/** Flowvar Interface API */

void FlowVarAddStr(Flow *, uint8_t, uint8_t *, uint16_t);
void FlowVarAddInt(Flow *, uint8_t, uint32_t);
FlowVar *FlowVarGet(Flow *, uint8_t);
void FlowVarFree(FlowVar *);
void FlowVarPrint(GenericVar *);

#endif /* __FLOW_VAR_H__ */

