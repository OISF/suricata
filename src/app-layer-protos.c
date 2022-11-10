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

#include "suricata-common.h"
#include "app-layer-protos.h"

#define CASE_CODE(E)  case E: return #E

const char *AppProtoToString(AppProto alproto)
{
    const char *proto_name = NULL;
    enum AppProtoEnum proto = alproto;

    switch (proto) {
        case ALPROTO_HTTP1:
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
        case ALPROTO_JABBER:
            proto_name = "jabber";
            break;
        case ALPROTO_SMB:
            proto_name = "smb";
            break;
        case ALPROTO_DCERPC:
            proto_name = "dcerpc";
            break;
        case ALPROTO_IRC:
            proto_name = "irc";
            break;
        case ALPROTO_DNS:
            proto_name = "dns";
            break;
        case ALPROTO_MODBUS:
            proto_name = "modbus";
            break;
        case ALPROTO_ENIP:
            proto_name = "enip";
            break;
        case ALPROTO_DNP3:
            proto_name = "dnp3";
            break;
        case ALPROTO_NFS:
            proto_name = "nfs";
            break;
        case ALPROTO_NTP:
            proto_name = "ntp";
            break;
        case ALPROTO_FTPDATA:
            proto_name = "ftp-data";
            break;
        case ALPROTO_TFTP:
            proto_name = "tftp";
            break;
        case ALPROTO_IKE:
            proto_name = "ike";
            break;
        case ALPROTO_KRB5:
            proto_name = "krb5";
            break;
        case ALPROTO_QUIC:
            proto_name = "quic";
            break;
        case ALPROTO_DHCP:
            proto_name = "dhcp";
            break;
        case ALPROTO_SNMP:
            proto_name = "snmp";
            break;
        case ALPROTO_SIP:
            proto_name = "sip";
            break;
        case ALPROTO_RFB:
            proto_name = "rfb";
	    break;
        case ALPROTO_MQTT:
            proto_name = "mqtt";
            break;
        case ALPROTO_PGSQL:
            proto_name = "pgsql";
            break;
        case ALPROTO_TELNET:
            proto_name = "telnet";
            break;
        case ALPROTO_POP3:
            proto_name = "pop3";
            break;
        case ALPROTO_TEMPLATE:
            proto_name = "template";
            break;
        case ALPROTO_TEMPLATE_RUST:
            proto_name = "template-rust";
            break;
        case ALPROTO_RDP:
            proto_name = "rdp";
            break;
        case ALPROTO_HTTP2:
            proto_name = "http2";
            break;
        case ALPROTO_HTTP:
            proto_name = "http_any";
            break;
        case ALPROTO_BITTORRENT_DHT:
            proto_name = "bittorrent-dht";
            break;
        case ALPROTO_FAILED:
            proto_name = "failed";
            break;
#ifdef UNITTESTS
        case ALPROTO_TEST:
#endif
        case ALPROTO_MAX:
        case ALPROTO_UNKNOWN:
            break;
    }

    return proto_name;
}

AppProto StringToAppProto(const char *proto_name)
{
    if (proto_name == NULL) return ALPROTO_UNKNOWN;

    if (strcmp(proto_name, "http") == 0)
        return ALPROTO_HTTP;
    if (strcmp(proto_name, "http1") == 0)
        return ALPROTO_HTTP1;
    if (strcmp(proto_name,"ftp")==0) return ALPROTO_FTP;
    if (strcmp(proto_name, "ftp-data") == 0)
        return ALPROTO_FTPDATA;
    if (strcmp(proto_name, "tftp") == 0)
        return ALPROTO_TFTP;
    if (strcmp(proto_name,"smtp")==0) return ALPROTO_SMTP;
    if (strcmp(proto_name,"tls")==0) return ALPROTO_TLS;
    if (strcmp(proto_name,"ssh")==0) return ALPROTO_SSH;
    if (strcmp(proto_name,"imap")==0) return ALPROTO_IMAP;
    if (strcmp(proto_name,"jabber")==0) return ALPROTO_JABBER;
    if (strcmp(proto_name,"smb")==0) return ALPROTO_SMB;
    if (strcmp(proto_name,"dcerpc")==0) return ALPROTO_DCERPC;
    if (strcmp(proto_name,"irc")==0) return ALPROTO_IRC;
    if (strcmp(proto_name,"dns")==0) return ALPROTO_DNS;
    if (strcmp(proto_name,"modbus")==0) return ALPROTO_MODBUS;
    if (strcmp(proto_name,"enip")==0) return ALPROTO_ENIP;
    if (strcmp(proto_name,"dnp3")==0) return ALPROTO_DNP3;
    if (strcmp(proto_name,"nfs")==0) return ALPROTO_NFS;
    if (strcmp(proto_name,"ntp")==0) return ALPROTO_NTP;
    if (strcmp(proto_name, "ike") == 0)
        return ALPROTO_IKE;
    if (strcmp(proto_name,"krb5")==0) return ALPROTO_KRB5;
    if (strcmp(proto_name, "quic") == 0)
        return ALPROTO_QUIC;
    if (strcmp(proto_name,"dhcp")==0) return ALPROTO_DHCP;
    if (strcmp(proto_name,"snmp")==0) return ALPROTO_SNMP;
    if (strcmp(proto_name,"sip")==0) return ALPROTO_SIP;
    if (strcmp(proto_name,"rfb")==0) return ALPROTO_RFB;
    if (strcmp(proto_name,"mqtt")==0) return ALPROTO_MQTT;
    if (strcmp(proto_name, "pgsql") == 0)
        return ALPROTO_PGSQL;
    if (strcmp(proto_name, "telnet") == 0)
        return ALPROTO_TELNET;
    if (strcmp(proto_name, "pop3") == 0)
        return ALPROTO_POP3;
    if (strcmp(proto_name,"template")==0) return ALPROTO_TEMPLATE;
    if (strcmp(proto_name,"template-rust")==0) return ALPROTO_TEMPLATE_RUST;
    if (strcmp(proto_name,"rdp")==0) return ALPROTO_RDP;
    if (strcmp(proto_name,"http2")==0) return ALPROTO_HTTP2;
    if (strcmp(proto_name, "bittorrent-dht") == 0)
        return ALPROTO_BITTORRENT_DHT;
    if (strcmp(proto_name,"failed")==0) return ALPROTO_FAILED;

    return ALPROTO_UNKNOWN;
}
