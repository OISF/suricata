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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_ENGINE_EVENT_H__
#define __DETECT_ENGINE_EVENT_H__

#include "decode-events.h"

typedef struct DetectEngineEventData_ {
    uint8_t event;
} DetectEngineEventData;

/* prototypes */
void DetectEngineEventRegister (void);

/* supported decoder events */

#ifdef DETECT_EVENTS
struct DetectEngineEvents_ {
    char *event_name;
    uint8_t code;
} DEvents[] = {
    { "ipv4.pkt_too_small", IPV4_PKT_TOO_SMALL, },
    { "ipv4.hlen_too_small", IPV4_HLEN_TOO_SMALL, },
    { "ipv4.iplen_smaller_than_hlen", IPV4_IPLEN_SMALLER_THAN_HLEN, },
    { "ipv4.trunc_pkt", IPV4_TRUNC_PKT, },
    { "ipv4.opt_invalid", IPV4_OPT_INVALID, },
    { "ipv4.opt_invalid_len", IPV4_OPT_INVALID_LEN, },
    { "ipv4.opt_malformed", IPV4_OPT_MALFORMED, },
    { "ipv4.opt_pad_required", IPV4_OPT_PAD_REQUIRED, },
    { "ipv4.opt_eol_required", IPV4_OPT_EOL_REQUIRED, },
    { "ipv4.opt_duplicate", IPV4_OPT_DUPLICATE, },
    { "ipv4.opt_unknown", IPV4_OPT_UNKNOWN, },
    { "ipv4.wrong_ip_version", IPV4_WRONG_IP_VER, },
    { "ipv6.pkt_too_small", IPV6_PKT_TOO_SMALL, },
    { "ipv6.trunc_pkt", IPV6_TRUNC_PKT, },
    { "ipv6.trunc_exthdr", IPV6_TRUNC_EXTHDR, },
    { "ipv6.exthdr_dupl_fh", IPV6_EXTHDR_DUPL_FH, },
    { "ipv6.exthdr_useless_fh", IPV6_EXTHDR_USELESS_FH, },
    { "ipv6.exthdr_dupl_rh", IPV6_EXTHDR_DUPL_RH, },
    { "ipv6.exthdr_dupl_hh", IPV6_EXTHDR_DUPL_HH, },
    { "ipv6.exthdr_dupl_dh", IPV6_EXTHDR_DUPL_DH, },
    { "ipv6.exthdr_dupl_ah", IPV6_EXTHDR_DUPL_AH, },
    { "ipv6.exthdr_dupl_eh", IPV6_EXTHDR_DUPL_EH, },
    { "ipv6.exthdr_invalid_optlen", IPV6_EXTHDR_INVALID_OPTLEN, },
    { "ipv6.wrong_ip_version", IPV6_WRONG_IP_VER, },
    { "ipv6.exthdr_ah_res_not_null", IPV6_EXTHDR_AH_RES_NOT_NULL, },
    { "ipv6.hopopts_unknown_opt", IPV6_HOPOPTS_UNKNOWN_OPT, },
    { "ipv6.hopopts_only_padding", IPV6_HOPOPTS_ONLY_PADDING, },
    { "ipv6.dstopts_unknown_opt", IPV6_DSTOPTS_UNKNOWN_OPT, },
    { "ipv6.dstopts_only_padding", IPV6_DSTOPTS_ONLY_PADDING, },
    { "ipv6.icmpv4", IPV6_WITH_ICMPV4, },
    { "icmpv4.pkt_too_small", ICMPV4_PKT_TOO_SMALL, },
    { "icmpv4.unknown_type", ICMPV4_UNKNOWN_TYPE, },
    { "icmpv4.unknown_code", ICMPV4_UNKNOWN_CODE, },
    { "icmpv4.ipv4_trunc_pkt", ICMPV4_IPV4_TRUNC_PKT, },
    { "icmpv4.ipv4_unknown_ver", ICMPV4_IPV4_UNKNOWN_VER, },
    { "icmpv6.unknown_type", ICMPV6_UNKNOWN_TYPE,},
    { "icmpv6.unknown_code", ICMPV6_UNKNOWN_CODE,},
    { "icmpv6.pkt_too_small", ICMPV6_PKT_TOO_SMALL,},
    { "icmpv6.ipv6_unknown_version", ICMPV6_IPV6_UNKNOWN_VER,},
    { "icmpv6.ipv6_trunc_pkt", ICMPV6_IPV6_TRUNC_PKT,},
    { "tcp.pkt_too_small", TCP_PKT_TOO_SMALL, },
    { "tcp.hlen_too_small", TCP_HLEN_TOO_SMALL, },
    { "tcp.invalid_optlen", TCP_INVALID_OPTLEN, },
    { "tcp.opt_invalid_len", TCP_OPT_INVALID_LEN, },
    { "tcp.opt_duplicate", TCP_OPT_DUPLICATE, },
    { "udp.pkt_too_small", UDP_PKT_TOO_SMALL, },
    { "udp.hlen_too_small", UDP_HLEN_TOO_SMALL, },
    { "udp.hlen_invalid", UDP_HLEN_INVALID, },
    { "sll.pkt_too_small", SLL_PKT_TOO_SMALL, },
    { "ethernet.pkt_too_small", ETHERNET_PKT_TOO_SMALL, },
    { "ppp.pkt_too_small", PPP_PKT_TOO_SMALL, },
    { "ppp.vju_pkt_too_small", PPPVJU_PKT_TOO_SMALL, },
    { "ppp.ip4_pkt_too_small", PPPIPV4_PKT_TOO_SMALL, },
    { "ppp.ip6_pkt_too_small", PPPIPV6_PKT_TOO_SMALL, },
    { "ppp.wrong_type", PPP_WRONG_TYPE, }, /** unknown & invalid protocol */
    { "ppp.unsup_proto", PPP_UNSUP_PROTO, }, /** unsupported but valid protocol */
    { "pppoe.pkt_too_small", PPPOE_PKT_TOO_SMALL, },
    { "pppoe.wrong_code", PPPOE_WRONG_CODE, },
    { "pppoe.malformed_tags", PPPOE_MALFORMED_TAGS, },
    { "gre.pkt_too_small", GRE_PKT_TOO_SMALL, },
    { "gre.wrong_version", GRE_WRONG_VERSION, },
    { "gre.version0_recur", GRE_VERSION0_RECUR, },
    { "gre.version0_flags", GRE_VERSION0_FLAGS, },
    { "gre.version0_hdr_too_big", GRE_VERSION0_HDR_TOO_BIG, },
    { "gre.version0_malformed_sre_hdr", GRE_VERSION0_MALFORMED_SRE_HDR, },
    { "gre.version1_chksum", GRE_VERSION1_CHKSUM, },
    { "gre.version1_route", GRE_VERSION1_ROUTE, },
    { "gre.version1_ssr", GRE_VERSION1_SSR, },
    { "gre.version1_recur", GRE_VERSION1_RECUR, },
    { "gre.version1_flags", GRE_VERSION1_FLAGS, },
    { "gre.version1_no_key", GRE_VERSION1_NO_KEY, },
    { "gre.version1_wrong_protocol", GRE_VERSION1_WRONG_PROTOCOL, },
    { "gre.version1_malformed_sre_hdr", GRE_VERSION1_MALFORMED_SRE_HDR, },
    { "gre.version1_hdr_too_big", GRE_VERSION1_HDR_TOO_BIG, },
    { "ipraw.invalid_ip_version",IPRAW_INVALID_IPV, },
    { "vlan.header_too_small",VLAN_HEADER_TOO_SMALL, },
    { "vlan.unknown_type",VLAN_UNKNOWN_TYPE, },
    { "ipv4.frag_too_large", IPV4_FRAG_PKT_TOO_LARGE, },
    { "ipv4.frag_overlap", IPV4_FRAG_OVERLAP, },
    { "ipv6.frag_too_large", IPV6_FRAG_PKT_TOO_LARGE, },
    { "ipv6.frag_overlap", IPV6_FRAG_OVERLAP, },
    { "ipv6.ipv4_in_ipv6_too_small", IPV4_IN_IPV6_PKT_TOO_SMALL, },
    { "ipv6.ipv4_in_ipv6_wrong_version", IPV4_IN_IPV6_WRONG_IP_VER, },
    { "ipv6.ipv6_in_ipv6_too_small", IPV6_IN_IPV6_PKT_TOO_SMALL, },
    { "ipv6.ipv6_in_ipv6_wrong_version", IPV6_IN_IPV6_WRONG_IP_VER, },
    { "stream.3whs_ack_in_wrong_dir", STREAM_3WHS_ACK_IN_WRONG_DIR, },
    { "stream.3whs_async_wrong_seq", STREAM_3WHS_ASYNC_WRONG_SEQ, },
    { "stream.3whs_right_seq_wrong_ack_evasion", STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION, },
    { "stream.3whs_synack_in_wrong_direction", STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION, },
    { "stream.3whs_synack_resend_with_different_ack", STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK, },
    { "stream.3whs_synack_resend_with_diff_seq", STREAM_3WHS_SYNACK_RESEND_WITH_DIFF_SEQ, },
    { "stream.3whs_synack_toserver_on_syn_recv", STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV, },
    { "stream.3whs_synack_with_wrong_ack", STREAM_3WHS_SYNACK_WITH_WRONG_ACK, },
    { "stream.3whs_synack_flood", STREAM_3WHS_SYNACK_FLOOD, },
    { "stream.3whs_syn_resend_diff_seq_on_syn_recv", STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV, },
    { "stream.3whs_syn_toclient_on_syn_recv", STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV, },
    { "stream.3whs_wrong_seq_wrong_ack", STREAM_3WHS_WRONG_SEQ_WRONG_ACK, },
    { "stream.4whs_synack_with_wrong_ack", STREAM_4WHS_SYNACK_WITH_WRONG_ACK, },
    { "stream.4whs_synack_with_wrong_syn", STREAM_4WHS_SYNACK_WITH_WRONG_SYN, },
    { "stream.4whs_wrong_seq", STREAM_4WHS_WRONG_SEQ, },
    { "stream.4whs_invalid_ack", STREAM_4WHS_INVALID_ACK, },
    { "stream.closewait_ack_out_of_window", STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW, },
    { "stream.closewait_fin_out_of_window", STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW, },
    { "stream.closewait_pkt_before_last_ack", STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK, },
    { "stream.closewait_invalid_ack", STREAM_CLOSEWAIT_INVALID_ACK, },
    { "stream.closing_ack_wrong_seq", STREAM_CLOSING_ACK_WRONG_SEQ, },
    { "stream.closing_invalid_ack", STREAM_CLOSING_INVALID_ACK, },
    { "stream.est_packet_out_of_window", STREAM_EST_PACKET_OUT_OF_WINDOW, },
    { "stream.est_pkt_before_last_ack", STREAM_EST_PKT_BEFORE_LAST_ACK, },
    { "stream.est_synack_resend", STREAM_EST_SYNACK_RESEND, },
    { "stream.est_synack_resend_with_different_ack", STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK, },
    { "stream.est_synack_resend_with_diff_seq", STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ, },
    { "stream.est_synack_toserver", STREAM_EST_SYNACK_TOSERVER, },
    { "stream.est_syn_resend", STREAM_EST_SYN_RESEND, },
    { "stream.est_syn_resend_diff_seq", STREAM_EST_SYN_RESEND_DIFF_SEQ, },
    { "stream.est_syn_toclient", STREAM_EST_SYN_TOCLIENT, },
    { "stream.est_invalid_ack", STREAM_EST_INVALID_ACK, },
    { "stream.fin_invalid_ack", STREAM_FIN_INVALID_ACK, },
    { "stream.fin1_ack_wrong_seq", STREAM_FIN1_ACK_WRONG_SEQ, },
    { "stream.fin1_fin_wrong_seq", STREAM_FIN1_FIN_WRONG_SEQ, },
    { "stream.fin1_invalid_ack", STREAM_FIN1_INVALID_ACK, },
    { "stream.fin2_ack_wrong_seq", STREAM_FIN2_ACK_WRONG_SEQ, },
    { "stream.fin2_fin_wrong_seq", STREAM_FIN2_FIN_WRONG_SEQ, },
    { "stream.fin2_invalid_ack", STREAM_FIN2_INVALID_ACK, },
    { "stream.fin_but_no_session", STREAM_FIN_BUT_NO_SESSION, },
    { "stream.fin_out_of_window", STREAM_FIN_OUT_OF_WINDOW, },
    { "stream.lastack_ack_wrong_seq", STREAM_LASTACK_ACK_WRONG_SEQ, },
    { "stream.lastack_invalid_ack", STREAM_LASTACK_INVALID_ACK, },
    { "stream.rst_but_no_session", STREAM_RST_BUT_NO_SESSION, },
    { "stream.timewait_ack_wrong_seq", STREAM_TIMEWAIT_ACK_WRONG_SEQ, },
    { "stream.timewait_invalid_ack", STREAM_TIMEWAIT_INVALID_ACK, },
    { "stream.pkt_invalid_timestamp", STREAM_PKT_INVALID_TIMESTAMP, },
    { "stream.pkt_invalid_ack", STREAM_PKT_INVALID_ACK, },
    { "stream.pkt_broken_ack", STREAM_PKT_BROKEN_ACK, },
    { "stream.rst_invalid_ack", STREAM_RST_INVALID_ACK, },
    { "stream.shutdown_syn_resend", STREAM_SHUTDOWN_SYN_RESEND, },
    { "stream.pkt_retransmission", STREAM_PKT_RETRANSMISSION, },
    { "stream.reassembly_segment_before_base_seq", STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ, },
    { "stream.reassembly_no_segment", STREAM_REASSEMBLY_NO_SEGMENT, },
    { "stream.reassembly_seq_gap", STREAM_REASSEMBLY_SEQ_GAP, },
    { "stream.reassembly_overlap_different_data", STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA, },
    { NULL, 0 },
};
#endif /* DETECT_EVENTS */

#endif /*__DETECT_ENGINE_EVENT_H__ */

