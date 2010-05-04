/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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
 *
 * Decode the raw packet
 */

#include "suricata-common.h"
#include "decode.h"
#include "util-debug.h"

void DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    switch (p->tunnel_proto) {
        case PPP_OVER_GRE:
            return DecodePPP(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IP:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
       case VLAN_OVER_GRE:
            return DecodeVLAN(tv, dtv, p, pkt, len, pq);
        default:
            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", p->tunnel_proto);
            break;
    }
}

void DecodeRegisterPerfCounters(DecodeThreadVars *dtv, ThreadVars *tv)
{
    /* register counters */
    dtv->counter_pkts = SCPerfTVRegisterCounter("decoder.pkts", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_pkts_per_sec = SCPerfTVRegisterIntervalCounter("decoder.pkts_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
    dtv->counter_bytes = SCPerfTVRegisterCounter("decoder.bytes", tv,
                                                 SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_bytes_per_sec = SCPerfTVRegisterIntervalCounter("decoder.bytes_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
    dtv->counter_mbit_per_sec = SCPerfTVRegisterIntervalCounter("decoder.mbit_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
    dtv->counter_ipv4 = SCPerfTVRegisterCounter("decoder.ipv4", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_ipv6 = SCPerfTVRegisterCounter("decoder.ipv6", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_eth = SCPerfTVRegisterCounter("decoder.ethernet", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_raw = SCPerfTVRegisterCounter("decoder.raw", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_sll = SCPerfTVRegisterCounter("decoder.sll", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_tcp = SCPerfTVRegisterCounter("decoder.tcp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_udp = SCPerfTVRegisterCounter("decoder.udp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_icmpv4 = SCPerfTVRegisterCounter("decoder.icmpv4", tv,
                                                  SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_icmpv6 = SCPerfTVRegisterCounter("decoder.icmpv6", tv,
                                                  SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_ppp = SCPerfTVRegisterCounter("decoder.ppp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_pppoe = SCPerfTVRegisterCounter("decoder.pppoe", tv,
                                                 SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_gre = SCPerfTVRegisterCounter("decoder.gre", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_vlan = SCPerfTVRegisterCounter("decoder.vlan", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_avg_pkt_size = SCPerfTVRegisterAvgCounter("decoder.avg_pkt_size", tv,
                                                           SC_PERF_TYPE_DOUBLE, "NULL");
    dtv->counter_max_pkt_size = SCPerfTVRegisterMaxCounter("decoder.max_pkt_size", tv,
                                                           SC_PERF_TYPE_UINT64, "NULL");

    dtv->counter_defrag_ipv4_fragments =
        SCPerfTVRegisterCounter("defrag.ipv4.fragments", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv4_reassembled =
        SCPerfTVRegisterCounter("defrag.ipv4.reassembled", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv4_timeouts =
        SCPerfTVRegisterCounter("defrag.ipv4.timeouts", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_fragments =
        SCPerfTVRegisterCounter("defrag.ipv6.fragments", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_reassembled =
        SCPerfTVRegisterCounter("defrag.ipv6.reassembled", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_timeouts =
        SCPerfTVRegisterCounter("defrag.ipv6.timeouts", tv,
            SC_PERF_TYPE_UINT64, "NULL");

    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);

    return;
}
