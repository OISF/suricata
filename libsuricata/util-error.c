/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Error utility functions
 *
 * \todo Needs refining of the error codes.  Renaming with a prefix of SC_ERR,
 *       removal of duplicates and entries have to be made in util-error.c
 */

#include "util-error.h"

thread_local SCError sc_errno = SC_OK;
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

        CASE_CODE(SC_ENOMEM);
        CASE_CODE(SC_EINVAL);
        CASE_CODE(SC_ELIMIT);
        CASE_CODE(SC_EEXIST);

        CASE_CODE (SC_ERR_MAX);
    }

    return "UNKNOWN_ERROR";
}
