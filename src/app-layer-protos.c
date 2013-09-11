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
const char *TmModuleAlprotoToString(enum AppProto proto)
{
    const char *proto_name = NULL;

    switch (proto) {
        case ALPROTO_HTTP:
            proto_name = "http";
            break;
        case ALPROTO_FTP:
            proto_name = "ftp";
            break;
        case ALPROTO_SMTP:
            proto_name = "smtp";
            break;
        case ALPROTO_TLS:
            proto_name = "tls";
            break;
        case ALPROTO_SSH:
            proto_name = "ssh";
            break;
        case ALPROTO_IMAP:
            proto_name = "imap";
            break;
        case ALPROTO_MSN:
            proto_name = "msn";
            break;
        case ALPROTO_JABBER:
            proto_name = "jabber";
            break;
        case ALPROTO_SMB:
            proto_name = "smb";
            break;
        case ALPROTO_SMB2:
            proto_name = "smb2";
            break;
        case ALPROTO_DCERPC:
            proto_name = "dcerpc";
            break;
        case ALPROTO_DCERPC_UDP:
            proto_name = "dcerpcudp";
            break;
        case ALPROTO_IRC:
            proto_name = "irc";
            break;
        case ALPROTO_DNS_TCP:
            proto_name = "dnstcp";
            break;
        case ALPROTO_DNS_UDP:
            proto_name = "dnsudp";
            break;
        case ALPROTO_DNS:
            proto_name = "dns";
            break;
        case ALPROTO_FAILED:
#ifdef UNITTESTS
        case ALPROTO_TEST:
#endif
        case ALPROTO_MAX:
        case ALPROTO_UNKNOWN:
            break;
    }

    return proto_name;
}

