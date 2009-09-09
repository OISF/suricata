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
        CASE_CODE (SC_ERR_MEM_ALLOC);
        CASE_CODE (SC_OK);
        CASE_CODE (SC_PCRE_MATCH_FAILED);
        CASE_CODE (SC_LOG_MODULE_NOT_INIT);
        default:
            return "UNKNOWN_ERROR";
    }
}
