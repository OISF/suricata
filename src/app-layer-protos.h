/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __APP_LAYER_PROTOS_H__
#define __APP_LAYER_PROTOS_H__

enum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_HTTP,
    ALPROTO_FTP,
    ALPROTO_SMTP,
    ALPROTO_TLS, /* SSLv2, SSLv3 & TLSv1 */
    ALPROTO_SSH,
    ALPROTO_IMAP,
    ALPROTO_MSN,
    ALPROTO_JABBER,
    ALPROTO_SMB,
    ALPROTO_SMB2,
    ALPROTO_DCERPC,
    ALPROTO_DCERPC_UDP,
    ALPROTO_IRC,
    ALPROTO_DNS_UDP,
    ALPROTO_DNS_TCP,
    /* used by the probing parser when alproto detection fails
     * permanently for that particular stream */
    ALPROTO_FAILED,
#ifdef UNITTESTS
    ALPROTO_TEST,
#endif /* UNITESTS */
    /* keep last */
    ALPROTO_MAX,
};

const char *TmModuleAlprotoToString(int proto);

#endif /* __APP_LAYER_PROTOS_H__ */

