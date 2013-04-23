/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 */

#include "suricata-common.h"

#define CASE_CODE(E)  case E: return #E

/**
 * \brief Maps the ALPROTO_*, to its string equivalent
 *
 * \param proto app layer protocol id
 *
 * \retval string equivalent for the alproto
 */
const char *TmModuleAlprotoToString(int proto)
{
    switch (proto) {
        CASE_CODE (ALPROTO_UNKNOWN);
        CASE_CODE (ALPROTO_HTTP);
        CASE_CODE (ALPROTO_FTP);
        CASE_CODE (ALPROTO_SMTP);
        CASE_CODE (ALPROTO_TLS);
        CASE_CODE (ALPROTO_SSH);
        CASE_CODE (ALPROTO_IMAP);
        CASE_CODE (ALPROTO_MSN);
        CASE_CODE (ALPROTO_JABBER);
        CASE_CODE (ALPROTO_SMB);
        CASE_CODE (ALPROTO_SMB2);
        CASE_CODE (ALPROTO_DCERPC);
        CASE_CODE (ALPROTO_DCERPC_UDP);

        CASE_CODE (ALPROTO_DNS);
        CASE_CODE (ALPROTO_DNS_UDP);
        CASE_CODE (ALPROTO_DNS_TCP);

        default:
            return "ALPROTO_UNDEFINED";
    }
}

