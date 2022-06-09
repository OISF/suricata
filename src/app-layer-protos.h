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
    ALPROTO_JABBER,
    ALPROTO_SMB,
    ALPROTO_DCERPC,
    ALPROTO_IRC,

    ALPROTO_DNS,
    ALPROTO_MODBUS,
    ALPROTO_ENIP,
    ALPROTO_DNP3,
    ALPROTO_NFS,
    ALPROTO_NTP,
    ALPROTO_FTPDATA,
    ALPROTO_TFTP,
    ALPROTO_IKEV2,
    ALPROTO_KRB5,
    ALPROTO_DHCP,
    ALPROTO_SNMP,
    ALPROTO_SIP,
    ALPROTO_RFB,
    ALPROTO_MQTT,
    ALPROTO_TEMPLATE,
    ALPROTO_TEMPLATE_RUST,
    ALPROTO_RDP,
    ALPROTO_HTTP2,

    /* used by the probing parser when alproto detection fails
     * permanently for that particular stream */
    ALPROTO_FAILED,
#ifdef UNITTESTS
    ALPROTO_TEST,
#endif /* UNITESTS */
    /* keep last */
    ALPROTO_MAX,
};
// NOTE: if ALPROTO's get >= 256, update SignatureNonPrefilterStore

/* not using the enum as that is a unsigned int, so 4 bytes */
typedef uint16_t AppProto;

static inline bool AppProtoIsValid(AppProto a)
{
    return ((a > ALPROTO_UNKNOWN && a < ALPROTO_FAILED));
}

extern bool g_config_http1keywords_http2traffic;

// wether a signature AppProto matches a flow (or signature) AppProto
static inline bool AppProtoEquals(AppProto sigproto, AppProto alproto)
{
    if (alproto == ALPROTO_HTTP2 && g_config_http1keywords_http2traffic &&
            sigproto == ALPROTO_HTTP) {
        return true;
    } else if (sigproto == ALPROTO_DCERPC) {
        return (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB);
    }
    return (sigproto == alproto);
}

/**
 * \brief Maps the ALPROTO_*, to its string equivalent.
 *
 * \param alproto App layer protocol id.
 *
 * \retval String equivalent for the alproto.
 */
const char *AppProtoToString(AppProto alproto);

/**
 * \brief Maps a string to its ALPROTO_* equivalent.
 *
 * \param String equivalent for the alproto.
 *
 * \retval alproto App layer protocol id, or ALPROTO_UNKNOWN.
 */
AppProto StringToAppProto(const char *proto_name);

#endif /* __APP_LAYER_PROTOS_H__ */
