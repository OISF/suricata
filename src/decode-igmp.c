/* Copyright (C) 2026 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "decode.h"
#include "util-debug.h"

#define IGMP_TYPE_MEMBERSHIP_QUERY     0x11
#define IGMP_TYPE_MEMBERSHIP_REPORT_V1 0x12
#define IGMP_TYPE_MEMBERSHIP_REPORT_V2 0x16
#define IGMP_TYPE_LEAVE_GROUP_V2       0x17
#define IGMP_TYPE_MEMBERSHIP_REPORT_V3 0x22

/* Data size: IP segment size (64k), minus IP header + RA option (24),
 * minus IGMPv3 header (12).
 * Divided by 4 bytes per address. */
#define IGMP_V3_MAX_N_SOURCES (65535 - 24 - 12) / 4

/* RGMP requires a specific dest address 224.0.0.25. */
#define RGMP_DEST_ADDRESS 0xe0000019

typedef struct IGMPv3MemberQueryHdr_ {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_address;
    uint8_t s_qrv;
    uint8_t qqic;
    uint16_t n_sources;
    /* Followed by source addresses */
} IGMPv3MemberQueryHdr;

typedef struct IGMPv3MemberReportGroupRecord_ {
    uint8_t type;
    uint8_t aux_data_len; /**< in units of 32-bit words */
    uint16_t n_sources;
    uint32_t mcast_addr;
    // source address
    // aux data
} IGMPv3MemberReportGroupRecord;

typedef struct IGMPv3MemberReportHdr_ {
    uint8_t type;
    uint8_t res;
    uint16_t checksum;
    uint16_t flags;
    uint16_t n_group_recs;
    /* Followed by group records */

} IGMPv3MemberReportHdr;

int DecodeIGMP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsCounterIncr(&tv->stats, dtv->counter_igmp);

    if (len < sizeof(IGMPHdr)) {
        ENGINE_SET_INVALID_EVENT(p, IGMP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    const IGMPHdr *igmp = PacketSetIGMP(p, pkt);
    p->proto = IPPROTO_IGMP;
    uint8_t version;

    /* see if we're RGMP (RFC 3488):
     * "All RGMP messages are sent with TTL 1, to destination address 224.0.0.25."
     */
    bool rgmp = false;
    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        const uint8_t pttl = IPV4_GET_RAW_IPTTL(ip4h);
        /* if packet is of the correct length (header size 8) to the correct address
         * and has a ttl of 1, we consider it RGMP. */
        if (len == 8 && RGMP_DEST_ADDRESS == SCNtohl(p->dst.address.address_un_data32[0]) &&
                pttl == 1) {
            SCLogDebug("RGMP (RFC 3488)");
            rgmp = true;
        }
    }

    /* For IGMPv3 Membership Query, we need to handle additional fields */
    if (igmp->type == IGMP_TYPE_MEMBERSHIP_QUERY) {
        if (len >= 12) {
            const IGMPv3MemberQueryHdr *igmpv3 = (const IGMPv3MemberQueryHdr *)pkt;
            const uint32_t n_sources = SCNtohs(igmpv3->n_sources);
            if (n_sources > IGMP_V3_MAX_N_SOURCES) {
                ENGINE_SET_INVALID_EVENT(p, IGMP_MALFORMED);
                return TM_ECODE_FAILED;
            }

            const uint32_t header_len =
                    sizeof(IGMPv3MemberQueryHdr) + (n_sources * sizeof(uint32_t));
            if (len < header_len) {
                SCLogDebug("len %u < header_len %u", len, header_len);
                ENGINE_SET_INVALID_EVENT(p, IGMP_V3_PKT_TOO_SMALL);
                return TM_ECODE_FAILED;
            }
            if (header_len >= UINT16_MAX) {
                ENGINE_SET_INVALID_EVENT(p, IGMP_MALFORMED);
                return TM_ECODE_FAILED;
            }
            p->l4.vars.igmp.hlen = (uint16_t)header_len;
            p->payload = (uint8_t *)pkt + header_len;
            p->payload_len = (uint16_t)(len - header_len);
            version = 3;
        } else {
            if (igmp->max_resp_time == 0) {
                version = 1;
            } else {
                version = 2;
            }
            p->l4.vars.igmp.hlen = (uint16_t)sizeof(IGMPHdr);
            p->payload = (uint8_t *)pkt + sizeof(IGMPHdr);
            p->payload_len = (uint16_t)(len - sizeof(IGMPHdr));
        }

    } else if (igmp->type == IGMP_TYPE_MEMBERSHIP_REPORT_V3) {
        const IGMPv3MemberReportHdr *igmpv3 = (const IGMPv3MemberReportHdr *)pkt;
        const uint32_t n_group_recs = SCNtohs(igmpv3->n_group_recs);
        uint32_t header_len = sizeof(IGMPv3MemberReportHdr);

        /* parse group records */
        for (uint32_t i = 0; i < n_group_recs; i++) {
            if (len - header_len < sizeof(IGMPv3MemberReportGroupRecord)) {
                SCLogDebug("len %u - header_len %u < IGMPv3MemberReportGroupRecord %u", len,
                        header_len, (uint32_t)sizeof(IGMPv3MemberReportGroupRecord));
                ENGINE_SET_INVALID_EVENT(p, IGMP_V3_PKT_TOO_SMALL);
                return TM_ECODE_FAILED;
            }

            const IGMPv3MemberReportGroupRecord *grec =
                    (const IGMPv3MemberReportGroupRecord *)(pkt + header_len);
            header_len += sizeof(IGMPv3MemberReportGroupRecord);

            if (len - header_len < (uint32_t)(grec->aux_data_len * sizeof(uint32_t))) {
                SCLogDebug("len %u - header_len %u aux_data_len %u", len, header_len,
                        (uint32_t)grec->aux_data_len);
                ENGINE_SET_INVALID_EVENT(p, IGMP_MALFORMED);
                return TM_ECODE_FAILED;
            }
            header_len += (uint32_t)(grec->aux_data_len * sizeof(uint32_t));

            uint32_t sources_len = (uint32_t)SCNtohs(grec->n_sources) * (uint32_t)sizeof(uint32_t);
            if (len - header_len < sources_len) {
                SCLogDebug("len %u - header_len %u sources_len %u", len, header_len, sources_len);
                ENGINE_SET_INVALID_EVENT(p, IGMP_MALFORMED);
                return TM_ECODE_FAILED;
            }
            header_len += sources_len;
        }
        if (header_len >= UINT16_MAX) {
            ENGINE_SET_INVALID_EVENT(p, IGMP_MALFORMED);
            return TM_ECODE_FAILED;
        }
        p->l4.vars.igmp.hlen = (uint16_t)header_len;
        p->payload = (uint8_t *)pkt + header_len;
        p->payload_len = (uint16_t)(len - header_len);
        version = 3;

    } else {
        if (igmp->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1) {
            version = 1;

        } else if (igmp->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2 ||
                   igmp->type == IGMP_TYPE_LEAVE_GROUP_V2) {
            version = 2;
        } else {
            version = 255;
        }

        p->l4.vars.igmp.hlen = (uint16_t)sizeof(IGMPHdr);
        p->payload = (uint8_t *)pkt + sizeof(IGMPHdr);
        p->payload_len = (uint16_t)(len - sizeof(IGMPHdr));
    }
    p->l4.vars.igmp.version = version;
    p->l4.vars.igmp.rgmp = rgmp;

    return TM_ECODE_OK;
}
