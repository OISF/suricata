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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef SURICATA_APP_LAYER_PROTOS_H
#define SURICATA_APP_LAYER_PROTOS_H

enum AppProtoEnum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_HTTP1,
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
    ALPROTO_IKE,
    ALPROTO_KRB5,
    ALPROTO_QUIC,
    ALPROTO_DHCP,
    ALPROTO_SNMP,
    ALPROTO_SIP,
    ALPROTO_RFB,
    ALPROTO_MQTT,
    ALPROTO_PGSQL,
    ALPROTO_TELNET,
    ALPROTO_WEBSOCKET,
    ALPROTO_LDAP,
    ALPROTO_DOH2,
    ALPROTO_TEMPLATE,
    ALPROTO_RDP,
    ALPROTO_HTTP2,
    ALPROTO_BITTORRENT_DHT,
    ALPROTO_POP3,

    // signature-only (ie not seen in flow)
    // HTTP for any version (ALPROTO_HTTP1 (version 1) or ALPROTO_HTTP2)
    ALPROTO_HTTP,

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

// whether a signature AppProto matches a flow (or signature) AppProto
static inline bool AppProtoEquals(AppProto sigproto, AppProto alproto)
{
    if (sigproto == alproto) {
        return true;
    }
    switch (sigproto) {
        case ALPROTO_DNS:
            // a DNS signature matches on either DNS or DOH2 flows
            return (alproto == ALPROTO_DOH2) || (alproto == ALPROTO_DNS);
        case ALPROTO_HTTP2:
            // a HTTP2 signature matches on either HTTP2 or DOH2 flows
            return (alproto == ALPROTO_DOH2) || (alproto == ALPROTO_HTTP2);
        case ALPROTO_DOH2:
            // a DOH2 signature accepts dns, http2 or http generic keywords
            return (alproto == ALPROTO_DOH2) || (alproto == ALPROTO_HTTP2) ||
                   (alproto == ALPROTO_DNS) || (alproto == ALPROTO_HTTP);
        case ALPROTO_HTTP:
            return (alproto == ALPROTO_HTTP1) || (alproto == ALPROTO_HTTP2);
        case ALPROTO_DCERPC:
            return (alproto == ALPROTO_SMB);
    }
    return false;
}

// whether a signature AppProto matches a flow (or signature) AppProto
static inline AppProto AppProtoCommon(AppProto sigproto, AppProto alproto)
{
    switch (sigproto) {
        case ALPROTO_SMB:
            if (alproto == ALPROTO_DCERPC) {
                // ok to have dcerpc keywords in smb sig
                return ALPROTO_SMB;
            }
            break;
        case ALPROTO_HTTP:
            // we had a generic http sig, now version specific
            if (alproto == ALPROTO_HTTP1) {
                return ALPROTO_HTTP1;
            } else if (alproto == ALPROTO_HTTP2) {
                return ALPROTO_HTTP2;
            }
            break;
        case ALPROTO_HTTP1:
            // version-specific sig with a generic keyword
            if (alproto == ALPROTO_HTTP) {
                return ALPROTO_HTTP1;
            }
            break;
        case ALPROTO_HTTP2:
            if (alproto == ALPROTO_HTTP) {
                return ALPROTO_HTTP2;
            }
            break;
        case ALPROTO_DOH2:
            // DOH2 accepts different protocol keywords
            if (alproto == ALPROTO_HTTP || alproto == ALPROTO_HTTP2 || alproto == ALPROTO_DNS) {
                return ALPROTO_DOH2;
            }
            break;
    }
    if (sigproto != alproto) {
        return ALPROTO_FAILED;
    }
    return alproto;
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

#endif /* SURICATA_APP_LAYER_PROTOS_H */
