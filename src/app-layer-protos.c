/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "suricata-common.h"
#include "app-layer-protos.h"

const char *AppProtoStrings[ALPROTO_MAX] = {
    "unknown",        // ALPROTO_UNKNOWN,
    "http",           // ALPROTO_HTTP1
    "ftp",            // ALPROTO_FTP
    "smtp",           // ALPROTO_SMTP
    "tls",            // ALPROTO_TLS
    "ssh",            // ALPROTO_SSH
    "imap",           // ALPROTO_IMAP
    "jabber",         // ALPROTO_JABBER
    "smb",            // ALPROTO_SMB
    "dcerpc",         // ALPROTO_DCERPC
    "irc",            // ALPROTO_IRC
    "dns",            // ALPROTO_DNS
    "modbus",         // ALPROTO_MODBUS
    "enip",           // ALPROTO_ENIP
    "dnp3",           // ALPROTO_DNP3
    "nfs",            // ALPROTO_NFS
    "ntp",            // ALPROTO_NTP
    "ftp-data",       // ALPROTO_FTPDATA
    "tftp",           // ALPROTO_TFTP
    "ike",            // ALPROTO_IKE
    "krb5",           // ALPROTO_KRB5
    "quic",           // ALPROTO_QUIC
    "dhcp",           // ALPROTO_DHCP
    "snmp",           // ALPROTO_SNMP
    "sip",            // ALPROTO_SIP
    "rfb",            // ALPROTO_RFB
    "mqtt",           // ALPROTO_MQTT
    "pgsql",          // ALPROTO_PGSQL
    "telnet",         // ALPROTO_TELNET
    "template",       // ALPROTO_TEMPLATE
    "rdp",            // ALPROTO_RDP
    "http2",          // ALPROTO_HTTP2
    "bittorrent-dht", // ALPROTO_BITTORRENT_DHT
    "http_any",       // ALPROTO_HTTP
    "failed",         // ALPROTO_FAILED
#ifdef UNITTESTS
    "test", // ALPROTO_TEST
#endif
};

const char *AppProtoToString(AppProto alproto)
{
    const char *proto_name = NULL;
    if (alproto < sizeof(AppProtoStrings) / sizeof(const char *)) {
        proto_name = AppProtoStrings[alproto];
    }

    return proto_name;
}

AppProto StringToAppProto(const char *proto_name)
{
    if (proto_name == NULL)
        return ALPROTO_UNKNOWN;

    // We could use a Multi Pattern Matcher
    for (size_t i = 0; i < sizeof(AppProtoStrings) / sizeof(const char *); i++) {
        if (strcmp(proto_name, AppProtoStrings[i]) == 0)
            return ((AppProto)i);
    }

    return ALPROTO_UNKNOWN;
}
