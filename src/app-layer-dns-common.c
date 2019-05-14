/* Copyright (C) 2013-2014 Open Information Security Foundation
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
#include "app-layer-dns-common.h"

SCEnumCharMap dns_decoder_event_table[ ] = {
    { "UNSOLLICITED_RESPONSE",      DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE, },
    { "MALFORMED_DATA",             DNS_DECODER_EVENT_MALFORMED_DATA, },
    { "NOT_A_REQUEST",              DNS_DECODER_EVENT_NOT_A_REQUEST, },
    { "NOT_A_RESPONSE",             DNS_DECODER_EVENT_NOT_A_RESPONSE, },
    { "Z_FLAG_SET",                 DNS_DECODER_EVENT_Z_FLAG_SET, },
    { "FLOODED",                    DNS_DECODER_EVENT_FLOODED, },
    { "STATE_MEMCAP_REACHED",       DNS_DECODER_EVENT_STATE_MEMCAP_REACHED, },

    { NULL,                         -1 },
};

int DNSStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, dns_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "dns's enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

int DNSStateGetEventInfoById(int event_id, const char **event_name,
                             AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, dns_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "dns's enum map table.",  event_id);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

void DNSAppLayerRegisterGetEventInfo(uint8_t ipproto, AppProto alproto)
{
    AppLayerParserRegisterGetEventInfo(ipproto, alproto, DNSStateGetEventInfo);

    return;
}

void DNSAppLayerRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto)
{
    AppLayerParserRegisterGetEventInfoById(ipproto, alproto, DNSStateGetEventInfoById);

    return;
}

void DNSCreateTypeString(uint16_t type, char *str, size_t str_size)
{
    switch (type) {
        case DNS_RECORD_TYPE_A:
            snprintf(str, str_size, "A");
            break;
        case DNS_RECORD_TYPE_NS:
            snprintf(str, str_size, "NS");
            break;
        case DNS_RECORD_TYPE_AAAA:
            snprintf(str, str_size, "AAAA");
            break;
        case DNS_RECORD_TYPE_CNAME:
            snprintf(str, str_size, "CNAME");
            break;
        case DNS_RECORD_TYPE_TXT:
            snprintf(str, str_size, "TXT");
            break;
        case DNS_RECORD_TYPE_MX:
            snprintf(str, str_size, "MX");
            break;
        case DNS_RECORD_TYPE_SOA:
            snprintf(str, str_size, "SOA");
            break;
        case DNS_RECORD_TYPE_PTR:
            snprintf(str, str_size, "PTR");
            break;
        case DNS_RECORD_TYPE_SIG:
            snprintf(str, str_size, "SIG");
            break;
        case DNS_RECORD_TYPE_KEY:
            snprintf(str, str_size, "KEY");
            break;
        case DNS_RECORD_TYPE_WKS:
            snprintf(str, str_size, "WKS");
            break;
        case DNS_RECORD_TYPE_TKEY:
            snprintf(str, str_size, "TKEY");
            break;
        case DNS_RECORD_TYPE_TSIG:
            snprintf(str, str_size, "TSIG");
            break;
        case DNS_RECORD_TYPE_ANY:
            snprintf(str, str_size, "ANY");
            break;
        case DNS_RECORD_TYPE_RRSIG:
            snprintf(str, str_size, "RRSIG");
            break;
        case DNS_RECORD_TYPE_NSEC:
            snprintf(str, str_size, "NSEC");
            break;
        case DNS_RECORD_TYPE_DNSKEY:
            snprintf(str, str_size, "DNSKEY");
            break;
        case DNS_RECORD_TYPE_HINFO:
            snprintf(str, str_size, "HINFO");
            break;
        case DNS_RECORD_TYPE_MINFO:
            snprintf(str, str_size, "MINFO");
            break;
        case DNS_RECORD_TYPE_RP:
            snprintf(str, str_size, "RP");
            break;
        case DNS_RECORD_TYPE_AFSDB:
            snprintf(str, str_size, "AFSDB");
            break;
        case DNS_RECORD_TYPE_X25:
            snprintf(str, str_size, "X25");
            break;
        case DNS_RECORD_TYPE_ISDN:
            snprintf(str, str_size, "ISDN");
            break;
        case DNS_RECORD_TYPE_RT:
            snprintf(str, str_size, "RT");
            break;
        case DNS_RECORD_TYPE_NSAP:
            snprintf(str, str_size, "NSAP");
            break;
        case DNS_RECORD_TYPE_NSAPPTR:
            snprintf(str, str_size, "NSAPPTR");
            break;
        case DNS_RECORD_TYPE_PX:
            snprintf(str, str_size, "PX");
            break;
        case DNS_RECORD_TYPE_GPOS:
            snprintf(str, str_size, "GPOS");
            break;
        case DNS_RECORD_TYPE_LOC:
            snprintf(str, str_size, "LOC");
            break;
        case DNS_RECORD_TYPE_SRV:
            snprintf(str, str_size, "SRV");
            break;
        case DNS_RECORD_TYPE_ATMA:
            snprintf(str, str_size, "ATMA");
            break;
        case DNS_RECORD_TYPE_NAPTR:
            snprintf(str, str_size, "NAPTR");
            break;
        case DNS_RECORD_TYPE_KX:
            snprintf(str, str_size, "KX");
            break;
        case DNS_RECORD_TYPE_CERT:
            snprintf(str, str_size, "CERT");
            break;
        case DNS_RECORD_TYPE_A6:
            snprintf(str, str_size, "A6");
            break;
        case DNS_RECORD_TYPE_DNAME:
            snprintf(str, str_size, "DNAME");
            break;
        case DNS_RECORD_TYPE_OPT:
            snprintf(str, str_size, "OPT");
            break;
        case DNS_RECORD_TYPE_APL:
            snprintf(str, str_size, "APL");
            break;
        case DNS_RECORD_TYPE_DS:
            snprintf(str, str_size, "DS");
            break;
        case DNS_RECORD_TYPE_SSHFP:
            snprintf(str, str_size, "SSHFP");
            break;
        case DNS_RECORD_TYPE_IPSECKEY:
            snprintf(str, str_size, "IPSECKEY");
            break;
        case DNS_RECORD_TYPE_DHCID:
            snprintf(str, str_size, "DHCID");
            break;
        case DNS_RECORD_TYPE_NSEC3:
            snprintf(str, str_size, "NSEC3");
            break;
        case DNS_RECORD_TYPE_NSEC3PARAM:
            snprintf(str, str_size, "NSEC3PARAM");
            break;
        case DNS_RECORD_TYPE_TLSA:
            snprintf(str, str_size, "TLSA");
            break;
        case DNS_RECORD_TYPE_HIP:
            snprintf(str, str_size, "HIP");
            break;
        case DNS_RECORD_TYPE_CDS:
            snprintf(str, str_size, "CDS");
            break;
        case DNS_RECORD_TYPE_CDNSKEY:
            snprintf(str, str_size, "CDNSKEY");
            break;
        case DNS_RECORD_TYPE_MAILA:
            snprintf(str, str_size, "MAILA");
            break;
        case DNS_RECORD_TYPE_URI:
            snprintf(str, str_size, "URI");
            break;
        case DNS_RECORD_TYPE_MB:
            snprintf(str, str_size, "MB");
            break;
        case DNS_RECORD_TYPE_MG:
            snprintf(str, str_size, "MG");
            break;
        case DNS_RECORD_TYPE_MR:
            snprintf(str, str_size, "MR");
            break;
        case DNS_RECORD_TYPE_NULL:
            snprintf(str, str_size, "NULL");
            break;
        case DNS_RECORD_TYPE_SPF:
            snprintf(str, str_size, "SPF");
            break;
        case DNS_RECORD_TYPE_NXT:
            snprintf(str, str_size, "NXT");
            break;
        case DNS_RECORD_TYPE_MD:
            snprintf(str, str_size, "MD");
            break;
        case DNS_RECORD_TYPE_MF:
            snprintf(str, str_size, "MF");
            break;
        default:
            snprintf(str, str_size, "%04x/%u", type, type);
    }
}

void DNSCreateRcodeString(uint8_t rcode, char *str, size_t str_size)
{
    switch (rcode) {
        case DNS_RCODE_NOERROR:
            snprintf(str, str_size, "NOERROR");
            break;
        case DNS_RCODE_FORMERR:
            snprintf(str, str_size, "FORMERR");
            break;
        case DNS_RCODE_SERVFAIL:
            snprintf(str, str_size, "SERVFAIL");
            break;
        case DNS_RCODE_NXDOMAIN:
            snprintf(str, str_size, "NXDOMAIN");
            break;
        case DNS_RCODE_NOTIMP:
            snprintf(str, str_size, "NOTIMP");
            break;
        case DNS_RCODE_REFUSED:
            snprintf(str, str_size, "REFUSED");
            break;
        case DNS_RCODE_YXDOMAIN:
            snprintf(str, str_size, "YXDOMAIN");
            break;
        case DNS_RCODE_YXRRSET:
            snprintf(str, str_size, "YXRRSET");
            break;
        case DNS_RCODE_NXRRSET:
            snprintf(str, str_size, "NXRRSET");
            break;
        case DNS_RCODE_NOTAUTH:
            snprintf(str, str_size, "NOTAUTH");
            break;
        case DNS_RCODE_NOTZONE:
            snprintf(str, str_size, "NOTZONE");
            break;
        /* these are the same, need more logic */
        case DNS_RCODE_BADVERS:
        //case DNS_RCODE_BADSIG:
            snprintf(str, str_size, "BADVERS/BADSIG");
            break;
        case DNS_RCODE_BADKEY:
            snprintf(str, str_size, "BADKEY");
            break;
        case DNS_RCODE_BADTIME:
            snprintf(str, str_size, "BADTIME");
            break;
        case DNS_RCODE_BADMODE:
            snprintf(str, str_size, "BADMODE");
            break;
        case DNS_RCODE_BADNAME:
            snprintf(str, str_size, "BADNAME");
            break;
        case DNS_RCODE_BADALG:
            snprintf(str, str_size, "BADALG");
            break;
        case DNS_RCODE_BADTRUNC:
            snprintf(str, str_size, "BADTRUNC");
            break;
        default:
            SCLogDebug("could not map DNS rcode to name, bug!");
            snprintf(str, str_size, "%04x/%u", rcode, rcode);
    }
}
