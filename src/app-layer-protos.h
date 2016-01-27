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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_PROTOS_H__
#define __APP_LAYER_PROTOS_H__

enum AppProtoEnum {
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
    ALPROTO_IRC,

    ALPROTO_DNS,
    ALPROTO_MODBUS,
    ALPROTO_TEMPLATE,

    /* used by the probing parser when alproto detection fails
     * permanently for that particular stream */
    ALPROTO_FAILED,
#ifdef UNITTESTS
    ALPROTO_TEST,
#endif /* UNITESTS */
    /* keep last */
    ALPROTO_MAX,
};

/* not using the enum as that is a unsigned int, so 4 bytes */
typedef uint16_t AppProto;

/**
 * \brief Maps the ALPROTO_*, to its string equivalent.
 *
 * \param alproto App layer protocol id.
 *
 * \retval String equivalent for the alproto.
 */
const char *AppProtoToString(AppProto alproto);

#endif /* __APP_LAYER_PROTOS_H__ */
