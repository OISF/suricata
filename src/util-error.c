/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "util-error.h"

#define CASE_CODE(E)  case E: return #E

/**
 * \brief Maps the error code, to its string equivalent
 *
 * \param The error code
 *
 * \retval The string equivalent for the error code
 */
const char * SCErrorToString(SCError err)
{
    switch (err) {
        CASE_CODE (SC_OK);
        CASE_CODE (SC_ERR_MEM_ALLOC);
        CASE_CODE (SC_PCRE_MATCH_FAILED);
        CASE_CODE (SC_PCRE_GET_SUBSTRING_FAILED);
        CASE_CODE (SC_PCRE_COMPILE_FAILED);
        CASE_CODE (SC_PCRE_STUDY_FAILED);
        CASE_CODE (SC_PCRE_PARSE_FAILED);
        CASE_CODE (SC_LOG_MODULE_NOT_INIT);
        CASE_CODE (SC_LOG_FG_FILTER_MATCH_FAILED);
        CASE_CODE (SC_COUNTER_EXCEEDED);
        CASE_CODE (SC_INVALID_CHECKSUM);
        CASE_CODE (SC_SPRINTF_ERROR);
        CASE_CODE (SC_INVALID_ARGUMENT);
        CASE_CODE (SC_SPINLOCK_ERROR);
        CASE_CODE (SC_INVALID_ENUM_MAP);
        CASE_CODE (SC_INVALID_IP_NETBLOCK);
        CASE_CODE (SC_INVALID_IPV4_ADDR);
        CASE_CODE (SC_INVALID_IPV6_ADDR);
        CASE_CODE (SC_COMPLETE_PORT_SPACE_NEGATED);
        CASE_CODE (SC_NO_PORTS_LEFT_AFTER_MERGE);
        CASE_CODE (SC_NEGATED_VALUE_IN_PORT_RANGE);
        CASE_CODE (SC_PORT_PARSE_INSERT_STRING_ERR);
        CASE_CODE (SC_UNREACHABLE_CODE_REACHED);
        CASE_CODE (SC_INVALID_NUMERIC_VALUE);
        CASE_CODE (SC_NUMERIC_VALUE_ERANGE);
        CASE_CODE (SC_INVALID_NUM_BYTES);
        CASE_CODE (SC_ERR_ARG_LEN_LONG);
        CASE_CODE (SC_ALPARSER_ERR);
        default:
            return "UNKNOWN_ERROR";
    }
}
