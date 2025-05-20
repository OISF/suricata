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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef SURICATA_OUTPUT_JSON_DNS_H
#define SURICATA_OUTPUT_JSON_DNS_H

#define DNS_LOG_REQUESTS  BIT_U64(0)
#define DNS_LOG_RESPONSES BIT_U64(1)

#define DNS_LOG_A          BIT_U64(2)
#define DNS_LOG_NS         BIT_U64(3)
#define DNS_LOG_MD         BIT_U64(4)
#define DNS_LOG_MF         BIT_U64(5)
#define DNS_LOG_CNAME      BIT_U64(6)
#define DNS_LOG_SOA        BIT_U64(7)
#define DNS_LOG_MB         BIT_U64(8)
#define DNS_LOG_MG         BIT_U64(9)
#define DNS_LOG_MR         BIT_U64(10)
#define DNS_LOG_NULL       BIT_U64(11)
#define DNS_LOG_WKS        BIT_U64(12)
#define DNS_LOG_PTR        BIT_U64(13)
#define DNS_LOG_HINFO      BIT_U64(14)
#define DNS_LOG_MINFO      BIT_U64(15)
#define DNS_LOG_MX         BIT_U64(16)
#define DNS_LOG_TXT        BIT_U64(17)
#define DNS_LOG_RP         BIT_U64(18)
#define DNS_LOG_AFSDB      BIT_U64(19)
#define DNS_LOG_X25        BIT_U64(20)
#define DNS_LOG_ISDN       BIT_U64(21)
#define DNS_LOG_RT         BIT_U64(22)
#define DNS_LOG_NSAP       BIT_U64(23)
#define DNS_LOG_NSAPPTR    BIT_U64(24)
#define DNS_LOG_SIG        BIT_U64(25)
#define DNS_LOG_KEY        BIT_U64(26)
#define DNS_LOG_PX         BIT_U64(27)
#define DNS_LOG_GPOS       BIT_U64(28)
#define DNS_LOG_AAAA       BIT_U64(29)
#define DNS_LOG_LOC        BIT_U64(30)
#define DNS_LOG_NXT        BIT_U64(31)
#define DNS_LOG_SRV        BIT_U64(32)
#define DNS_LOG_ATMA       BIT_U64(33)
#define DNS_LOG_NAPTR      BIT_U64(34)
#define DNS_LOG_KX         BIT_U64(35)
#define DNS_LOG_CERT       BIT_U64(36)
#define DNS_LOG_A6         BIT_U64(37)
#define DNS_LOG_DNAME      BIT_U64(38)
#define DNS_LOG_OPT        BIT_U64(39)
#define DNS_LOG_APL        BIT_U64(40)
#define DNS_LOG_DS         BIT_U64(41)
#define DNS_LOG_SSHFP      BIT_U64(42)
#define DNS_LOG_IPSECKEY   BIT_U64(43)
#define DNS_LOG_RRSIG      BIT_U64(44)
#define DNS_LOG_NSEC       BIT_U64(45)
#define DNS_LOG_DNSKEY     BIT_U64(46)
#define DNS_LOG_DHCID      BIT_U64(47)
#define DNS_LOG_NSEC3      BIT_U64(48)
#define DNS_LOG_NSEC3PARAM BIT_U64(49)
#define DNS_LOG_TLSA       BIT_U64(50)
#define DNS_LOG_HIP        BIT_U64(51)
#define DNS_LOG_CDS        BIT_U64(52)
#define DNS_LOG_CDNSKEY    BIT_U64(53)
#define DNS_LOG_SPF        BIT_U64(54)
#define DNS_LOG_TKEY       BIT_U64(55)
#define DNS_LOG_TSIG       BIT_U64(56)
#define DNS_LOG_MAILA      BIT_U64(57)
#define DNS_LOG_ANY        BIT_U64(58)
#define DNS_LOG_URI        BIT_U64(59)

#define DNS_LOG_FORMAT_GROUPED  BIT_U64(60)
#define DNS_LOG_FORMAT_DETAILED BIT_U64(61)
#define DNS_LOG_HTTPS           BIT_U64(62)

#define DNS_LOG_FORMAT_ALL (DNS_LOG_FORMAT_GROUPED | DNS_LOG_FORMAT_DETAILED)
#define DNS_LOG_ALL_RRTYPES                                                                        \
    (~(uint64_t)(DNS_LOG_REQUESTS | DNS_LOG_RESPONSES | DNS_LOG_FORMAT_DETAILED |                  \
                 DNS_LOG_FORMAT_GROUPED))

typedef struct SCDnsLogFileCtx_ {
    OutputJsonCtx *eve_ctx;
    SCDnsLogConfig config;
} SCDnsLogFileCtx;

// bindgen: ignore
typedef struct SCDnsLogThread_ {
    SCDnsLogFileCtx *dnslog_ctx;
    OutputJsonThreadCtx *ctx;
} SCDnsLogThread;

void JsonDnsLogRegister(void);
void JsonDoh2LogRegister(void);

bool AlertJsonDns(void *vtx, SCJsonBuilder *js);
bool AlertJsonDoh2(void *vtx, SCJsonBuilder *js);

#endif /* SURICATA_OUTPUT_JSON_DNS_H */
