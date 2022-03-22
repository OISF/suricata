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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"

#include "decode-events.h"
/* code moved to app-layer-events */

const struct DecodeEvents_ DEvents[] = {
    /* IPV4 EVENTS */
    {
            "decoder.ipv4.pkt_too_small",
            IPV4_PKT_TOO_SMALL,
    },
    {
            "decoder.ipv4.hlen_too_small",
            IPV4_HLEN_TOO_SMALL,
    },
    {
            "decoder.ipv4.iplen_smaller_than_hlen",
            IPV4_IPLEN_SMALLER_THAN_HLEN,
    },
    {
            "decoder.ipv4.trunc_pkt",
            IPV4_TRUNC_PKT,
    },

    /* IPV4 OPTIONS */
    {
            "decoder.ipv4.opt_invalid",
            IPV4_OPT_INVALID,
    },
    {
            "decoder.ipv4.opt_invalid_len",
            IPV4_OPT_INVALID_LEN,
    },
    {
            "decoder.ipv4.opt_malformed",
            IPV4_OPT_MALFORMED,
    },
    {
            "decoder.ipv4.opt_pad_required",
            IPV4_OPT_PAD_REQUIRED,
    },
    {
            "decoder.ipv4.opt_eol_required",
            IPV4_OPT_EOL_REQUIRED,
    },
    {
            "decoder.ipv4.opt_duplicate",
            IPV4_OPT_DUPLICATE,
    },
    {
            "decoder.ipv4.opt_unknown",
            IPV4_OPT_UNKNOWN,
    },
    {
            "decoder.ipv4.wrong_ip_version",
            IPV4_WRONG_IP_VER,
    },
    {
            "decoder.ipv4.icmpv6",
            IPV4_WITH_ICMPV6,
    },

    /* ICMP EVENTS */
    {
            "decoder.icmpv4.pkt_too_small",
            ICMPV4_PKT_TOO_SMALL,
    },
    {
            "decoder.icmpv4.unknown_type",
            ICMPV4_UNKNOWN_TYPE,
    },
    {
            "decoder.icmpv4.unknown_code",
            ICMPV4_UNKNOWN_CODE,
    },
    {
            "decoder.icmpv4.ipv4_trunc_pkt",
            ICMPV4_IPV4_TRUNC_PKT,
    },
    {
            "decoder.icmpv4.ipv4_unknown_ver",
            ICMPV4_IPV4_UNKNOWN_VER,
    },

    /* ICMPv6 EVENTS */
    {
            "decoder.icmpv6.unknown_type",
            ICMPV6_UNKNOWN_TYPE,
    },
    {
            "decoder.icmpv6.unknown_code",
            ICMPV6_UNKNOWN_CODE,
    },
    {
            "decoder.icmpv6.pkt_too_small",
            ICMPV6_PKT_TOO_SMALL,
    },
    {
            "decoder.icmpv6.ipv6_unknown_version",
            ICMPV6_IPV6_UNKNOWN_VER,
    },
    {
            "decoder.icmpv6.ipv6_trunc_pkt",
            ICMPV6_IPV6_TRUNC_PKT,
    },
    {
            "decoder.icmpv6.mld_message_with_invalid_hl",
            ICMPV6_MLD_MESSAGE_WITH_INVALID_HL,
    },
    {
            "decoder.icmpv6.unassigned_type",
            ICMPV6_UNASSIGNED_TYPE,
    },
    {
            "decoder.icmpv6.experimentation_type",
            ICMPV6_EXPERIMENTATION_TYPE,
    },

    /* IPV6 EVENTS */
    {
            "decoder.ipv6.pkt_too_small",
            IPV6_PKT_TOO_SMALL,
    },
    {
            "decoder.ipv6.trunc_pkt",
            IPV6_TRUNC_PKT,
    },
    {
            "decoder.ipv6.trunc_exthdr",
            IPV6_TRUNC_EXTHDR,
    },
    {
            "decoder.ipv6.exthdr_dupl_fh",
            IPV6_EXTHDR_DUPL_FH,
    },
    {
            "decoder.ipv6.exthdr_useless_fh",
            IPV6_EXTHDR_USELESS_FH,
    },
    {
            "decoder.ipv6.exthdr_dupl_rh",
            IPV6_EXTHDR_DUPL_RH,
    },
    {
            "decoder.ipv6.exthdr_dupl_hh",
            IPV6_EXTHDR_DUPL_HH,
    },
    {
            "decoder.ipv6.exthdr_dupl_dh",
            IPV6_EXTHDR_DUPL_DH,
    },
    {
            "decoder.ipv6.exthdr_dupl_ah",
            IPV6_EXTHDR_DUPL_AH,
    },
    {
            "decoder.ipv6.exthdr_dupl_eh",
            IPV6_EXTHDR_DUPL_EH,
    },
    {
            "decoder.ipv6.exthdr_invalid_optlen",
            IPV6_EXTHDR_INVALID_OPTLEN,
    },
    {
            "decoder.ipv6.wrong_ip_version",
            IPV6_WRONG_IP_VER,
    },
    {
            "decoder.ipv6.exthdr_ah_res_not_null",
            IPV6_EXTHDR_AH_RES_NOT_NULL,
    },
    {
            "decoder.ipv6.hopopts_unknown_opt",
            IPV6_HOPOPTS_UNKNOWN_OPT,
    },
    {
            "decoder.ipv6.hopopts_only_padding",
            IPV6_HOPOPTS_ONLY_PADDING,
    },
    {
            "decoder.ipv6.dstopts_unknown_opt",
            IPV6_DSTOPTS_UNKNOWN_OPT,
    },
    {
            "decoder.ipv6.dstopts_only_padding",
            IPV6_DSTOPTS_ONLY_PADDING,
    },
    {
            "decoder.ipv6.rh_type_0",
            IPV6_EXTHDR_RH_TYPE_0,
    },
    {
            "decoder.ipv6.zero_len_padn",
            IPV6_EXTHDR_ZERO_LEN_PADN,
    },
    {
            "decoder.ipv6.fh_non_zero_reserved_field",
            IPV6_FH_NON_ZERO_RES_FIELD,
    },
    {
            "decoder.ipv6.data_after_none_header",
            IPV6_DATA_AFTER_NONE_HEADER,
    },
    {
            "decoder.ipv6.unknown_next_header",
            IPV6_UNKNOWN_NEXT_HEADER,
    },
    {
            "decoder.ipv6.icmpv4",
            IPV6_WITH_ICMPV4,
    },

    /* TCP EVENTS */
    {
            "decoder.tcp.pkt_too_small",
            TCP_PKT_TOO_SMALL,
    },
    {
            "decoder.tcp.hlen_too_small",
            TCP_HLEN_TOO_SMALL,
    },
    {
            "decoder.tcp.invalid_optlen",
            TCP_INVALID_OPTLEN,
    },

    /* TCP OPTIONS */
    {
            "decoder.tcp.opt_invalid_len",
            TCP_OPT_INVALID_LEN,
    },
    {
            "decoder.tcp.opt_duplicate",
            TCP_OPT_DUPLICATE,
    },

    /* UDP EVENTS */
    {
            "decoder.udp.pkt_too_small",
            UDP_PKT_TOO_SMALL,
    },
    {
            "decoder.udp.hlen_too_small",
            UDP_HLEN_TOO_SMALL,
    },
    {
            "decoder.udp.hlen_invalid",
            UDP_HLEN_INVALID,
    },

    /* SLL EVENTS */
    {
            "decoder.sll.pkt_too_small",
            SLL_PKT_TOO_SMALL,
    },

    /* ETHERNET EVENTS */
    {
            "decoder.ethernet.pkt_too_small",
            ETHERNET_PKT_TOO_SMALL,
    },

    /* PPP EVENTS */
    {
            "decoder.ppp.pkt_too_small",
            PPP_PKT_TOO_SMALL,
    },
    {
            "decoder.ppp.vju_pkt_too_small",
            PPPVJU_PKT_TOO_SMALL,
    },
    {
            "decoder.ppp.ip4_pkt_too_small",
            PPPIPV4_PKT_TOO_SMALL,
    },
    {
            "decoder.ppp.ip6_pkt_too_small",
            PPPIPV6_PKT_TOO_SMALL,
    },
    {
            "decoder.ppp.wrong_type",
            PPP_WRONG_TYPE,
    }, /** unknown & invalid protocol */
    {
            "decoder.ppp.unsup_proto",
            PPP_UNSUP_PROTO,
    }, /** unsupported but valid protocol */

    /* PPPOE EVENTS */
    {
            "decoder.pppoe.pkt_too_small",
            PPPOE_PKT_TOO_SMALL,
    },
    {
            "decoder.pppoe.wrong_code",
            PPPOE_WRONG_CODE,
    },
    {
            "decoder.pppoe.malformed_tags",
            PPPOE_MALFORMED_TAGS,
    },

    /* GRE EVENTS */
    {
            "decoder.gre.pkt_too_small",
            GRE_PKT_TOO_SMALL,
    },
    {
            "decoder.gre.wrong_version",
            GRE_WRONG_VERSION,
    },
    {
            "decoder.gre.version0_recur",
            GRE_VERSION0_RECUR,
    },
    {
            "decoder.gre.version0_flags",
            GRE_VERSION0_FLAGS,
    },
    {
            "decoder.gre.version0_hdr_too_big",
            GRE_VERSION0_HDR_TOO_BIG,
    },
    {
            "decoder.gre.version0_malformed_sre_hdr",
            GRE_VERSION0_MALFORMED_SRE_HDR,
    },
    {
            "decoder.gre.version1_chksum",
            GRE_VERSION1_CHKSUM,
    },
    {
            "decoder.gre.version1_route",
            GRE_VERSION1_ROUTE,
    },
    {
            "decoder.gre.version1_ssr",
            GRE_VERSION1_SSR,
    },
    {
            "decoder.gre.version1_recur",
            GRE_VERSION1_RECUR,
    },
    {
            "decoder.gre.version1_flags",
            GRE_VERSION1_FLAGS,
    },
    {
            "decoder.gre.version1_no_key",
            GRE_VERSION1_NO_KEY,
    },
    {
            "decoder.gre.version1_wrong_protocol",
            GRE_VERSION1_WRONG_PROTOCOL,
    },
    {
            "decoder.gre.version1_malformed_sre_hdr",
            GRE_VERSION1_MALFORMED_SRE_HDR,
    },
    {
            "decoder.gre.version1_hdr_too_big",
            GRE_VERSION1_HDR_TOO_BIG,
    },

    /* VLAN EVENTS */
    {
            "decoder.vlan.header_too_small",
            VLAN_HEADER_TOO_SMALL,
    },
    {
            "decoder.vlan.unknown_type",
            VLAN_UNKNOWN_TYPE,
    },
    {
            "decoder.vlan.too_many_layers",
            VLAN_HEADER_TOO_MANY_LAYERS,
    },
    {
            "decoder.ieee8021ah.header_too_small",
            IEEE8021AH_HEADER_TOO_SMALL,
    },

    /* VNTAG EVENTS */
    {
            "decoder.vntag.header_too_small",
            VNTAG_HEADER_TOO_SMALL,
    },
    {
            "decoder.vntag.unknown_type",
            VNTAG_UNKNOWN_TYPE,
    },

    /* RAW EVENTS */
    {
            "decoder.ipraw.invalid_ip_version",
            IPRAW_INVALID_IPV,
    },

    /* LINKTYPE NULL EVENTS */
    {
            "decoder.ltnull.pkt_too_small",
            LTNULL_PKT_TOO_SMALL,
    },
    {
            "decoder.ltnull.unsupported_type",
            LTNULL_UNSUPPORTED_TYPE,
    },

    /* SCTP EVENTS */
    {
            "decoder.sctp.pkt_too_small",
            SCTP_PKT_TOO_SMALL,
    },

    /* ESP EVENTS */
    {
            "decoder.esp.pkt_too_small",
            ESP_PKT_TOO_SMALL,
    },

    /* Fragmentation reasembly events. */
    {
            "decoder.ipv4.frag_pkt_too_large",
            IPV4_FRAG_PKT_TOO_LARGE,
    },
    {
            "decoder.ipv6.frag_pkt_too_large",
            IPV6_FRAG_PKT_TOO_LARGE,
    },
    {
            "decoder.ipv4.frag_overlap",
            IPV4_FRAG_OVERLAP,
    },
    {
            "decoder.ipv6.frag_overlap",
            IPV6_FRAG_OVERLAP,
    },
    {
            "decoder.ipv6.frag_invalid_length",
            IPV6_FRAG_INVALID_LENGTH,
    },
    /* Fragment ignored due to internal error */
    {
            "decoder.ipv4.frag_ignored",
            IPV4_FRAG_IGNORED,
    },
    {
            "decoder.ipv6.frag_ignored",
            IPV6_FRAG_IGNORED,
    },

    /* IPv4 in IPv6 events */
    {
            "decoder.ipv6.ipv4_in_ipv6_too_small",
            IPV4_IN_IPV6_PKT_TOO_SMALL,
    },
    {
            "decoder.ipv6.ipv4_in_ipv6_wrong_version",
            IPV4_IN_IPV6_WRONG_IP_VER,
    },
    /* IPv6 in IPv6 events */
    {
            "decoder.ipv6.ipv6_in_ipv6_too_small",
            IPV6_IN_IPV6_PKT_TOO_SMALL,
    },
    {
            "decoder.ipv6.ipv6_in_ipv6_wrong_version",
            IPV6_IN_IPV6_WRONG_IP_VER,
    },

    /* MPLS events */
    {
            "decoder.mpls.header_too_small",
            MPLS_HEADER_TOO_SMALL,
    },
    {
            "decoder.mpls.pkt_too_small",
            MPLS_PKT_TOO_SMALL,
    },
    {
            "decoder.mpls.bad_label_router_alert",
            MPLS_BAD_LABEL_ROUTER_ALERT,
    },
    {
            "decoder.mpls.bad_label_implicit_null",
            MPLS_BAD_LABEL_IMPLICIT_NULL,
    },
    {
            "decoder.mpls.bad_label_reserved",
            MPLS_BAD_LABEL_RESERVED,
    },
    {
            "decoder.mpls.unknown_payload_type",
            MPLS_UNKNOWN_PAYLOAD_TYPE,
    },

    /* VXLAN events */
    {
            "decoder.vxlan.unknown_payload_type",
            VXLAN_UNKNOWN_PAYLOAD_TYPE,
    },

    /* Geneve events */
    {
            "decoder.geneve.unknown_payload_type",
            GENEVE_UNKNOWN_PAYLOAD_TYPE,
    },

    /* ERSPAN events */
    {
            "decoder.erspan.header_too_small",
            ERSPAN_HEADER_TOO_SMALL,
    },
    {
            "decoder.erspan.unsupported_version",
            ERSPAN_UNSUPPORTED_VERSION,
    },
    {
            "decoder.erspan.too_many_vlan_layers",
            ERSPAN_TOO_MANY_VLAN_LAYERS,
    },

    /* Cisco Fabric Path/DCE events. */
    {
            "decoder.dce.pkt_too_small",
            DCE_PKT_TOO_SMALL,
    },

    /* Cisco HDLC events. */
    {
            "decoder.chdlc.pkt_too_small",
            CHDLC_PKT_TOO_SMALL,
    },

    /* NSH events */
    {
            "decoder.nsh.header_too_small",
            NSH_HEADER_TOO_SMALL,
    },
    {
            "decoder.nsh.unsupported_version",
            NSH_UNSUPPORTED_VERSION,
    },
    {
            "decoder.nsh.bad_header_length",
            NSH_BAD_HEADER_LENGTH,
    },
    {
            "decoder.nsh.reserved_type",
            NSH_RESERVED_TYPE,
    },
    {
            "decoder.nsh.unsupported_type",
            NSH_UNSUPPORTED_TYPE,
    },
    {
            "decoder.nsh.unknown_payload",
            NSH_UNKNOWN_PAYLOAD,
    },
    {
            "decoder.too_many_layers",
            GENERIC_TOO_MANY_LAYERS,
    },

    /* STREAM EVENTS */
    {
            "stream.3whs_ack_in_wrong_dir",
            STREAM_3WHS_ACK_IN_WRONG_DIR,
    },
    {
            "stream.3whs_async_wrong_seq",
            STREAM_3WHS_ASYNC_WRONG_SEQ,
    },
    {
            "stream.3whs_right_seq_wrong_ack_evasion",
            STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION,
    },
    {
            "stream.3whs_synack_in_wrong_direction",
            STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION,
    },
    {
            "stream.3whs_synack_resend_with_diff_ack",
            STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK,
    },
    {
            "stream.3whs_synack_resend_with_diff_seq",
            STREAM_3WHS_SYNACK_RESEND_WITH_DIFF_SEQ,
    },
    {
            "stream.3whs_synack_toserver_on_syn_recv",
            STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV,
    },
    {
            "stream.3whs_synack_with_wrong_ack",
            STREAM_3WHS_SYNACK_WITH_WRONG_ACK,
    },
    {
            "stream.3whs_synack_flood",
            STREAM_3WHS_SYNACK_FLOOD,
    },
    {
            "stream.3whs_syn_resend_diff_seq_on_syn_recv",
            STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV,
    },
    {
            "stream.3whs_syn_toclient_on_syn_recv",
            STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV,
    },
    {
            "stream.3whs_wrong_seq_wrong_ack",
            STREAM_3WHS_WRONG_SEQ_WRONG_ACK,
    },
    {
            "stream.3whs_ack_data_inject",
            STREAM_3WHS_ACK_DATA_INJECT,
    },
    {
            "stream.4whs_synack_with_wrong_ack",
            STREAM_4WHS_SYNACK_WITH_WRONG_ACK,
    },
    {
            "stream.4whs_synack_with_wrong_syn",
            STREAM_4WHS_SYNACK_WITH_WRONG_SYN,
    },
    {
            "stream.4whs_wrong_seq",
            STREAM_4WHS_WRONG_SEQ,
    },
    {
            "stream.4whs_invalid_ack",
            STREAM_4WHS_INVALID_ACK,
    },
    {
            "stream.closewait_ack_out_of_window",
            STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW,
    },
    {
            "stream.closewait_fin_out_of_window",
            STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW,
    },
    {
            "stream.closewait_pkt_before_last_ack",
            STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK,
    },
    {
            "stream.closewait_invalid_ack",
            STREAM_CLOSEWAIT_INVALID_ACK,
    },
    {
            "stream.closing_ack_wrong_seq",
            STREAM_CLOSING_ACK_WRONG_SEQ,
    },
    {
            "stream.closing_invalid_ack",
            STREAM_CLOSING_INVALID_ACK,
    },
    {
            "stream.est_packet_out_of_window",
            STREAM_EST_PACKET_OUT_OF_WINDOW,
    },
    {
            "stream.est_pkt_before_last_ack",
            STREAM_EST_PKT_BEFORE_LAST_ACK,
    },
    {
            "stream.est_synack_resend",
            STREAM_EST_SYNACK_RESEND,
    },
    {
            "stream.est_synack_resend_with_diff_ack",
            STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK,
    },
    {
            "stream.est_synack_resend_with_diff_seq",
            STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ,
    },
    {
            "stream.est_synack_toserver",
            STREAM_EST_SYNACK_TOSERVER,
    },
    {
            "stream.est_syn_resend",
            STREAM_EST_SYN_RESEND,
    },
    {
            "stream.est_syn_resend_diff_seq",
            STREAM_EST_SYN_RESEND_DIFF_SEQ,
    },
    {
            "stream.est_syn_toclient",
            STREAM_EST_SYN_TOCLIENT,
    },
    {
            "stream.est_invalid_ack",
            STREAM_EST_INVALID_ACK,
    },
    {
            "stream.fin_invalid_ack",
            STREAM_FIN_INVALID_ACK,
    },
    {
            "stream.fin1_ack_wrong_seq",
            STREAM_FIN1_ACK_WRONG_SEQ,
    },
    {
            "stream.fin1_fin_wrong_seq",
            STREAM_FIN1_FIN_WRONG_SEQ,
    },
    {
            "stream.fin1_invalid_ack",
            STREAM_FIN1_INVALID_ACK,
    },
    {
            "stream.fin2_ack_wrong_seq",
            STREAM_FIN2_ACK_WRONG_SEQ,
    },
    {
            "stream.fin2_fin_wrong_seq",
            STREAM_FIN2_FIN_WRONG_SEQ,
    },
    {
            "stream.fin2_invalid_ack",
            STREAM_FIN2_INVALID_ACK,
    },
    {
            "stream.fin_but_no_session",
            STREAM_FIN_BUT_NO_SESSION,
    },
    {
            "stream.fin_out_of_window",
            STREAM_FIN_OUT_OF_WINDOW,
    },
    {
            "stream.fin_syn",
            STREAM_FIN_SYN,
    },
    {
            "stream.lastack_ack_wrong_seq",
            STREAM_LASTACK_ACK_WRONG_SEQ,
    },
    {
            "stream.lastack_invalid_ack",
            STREAM_LASTACK_INVALID_ACK,
    },
    {
            "stream.rst_but_no_session",
            STREAM_RST_BUT_NO_SESSION,
    },
    {
            "stream.timewait_ack_wrong_seq",
            STREAM_TIMEWAIT_ACK_WRONG_SEQ,
    },
    {
            "stream.timewait_invalid_ack",
            STREAM_TIMEWAIT_INVALID_ACK,
    },
    {
            "stream.shutdown_syn_resend",
            STREAM_SHUTDOWN_SYN_RESEND,
    },
    {
            "stream.pkt_invalid_timestamp",
            STREAM_PKT_INVALID_TIMESTAMP,
    },
    {
            "stream.pkt_invalid_ack",
            STREAM_PKT_INVALID_ACK,
    },
    {
            "stream.pkt_broken_ack",
            STREAM_PKT_BROKEN_ACK,
    },
    {
            "stream.rst_invalid_ack",
            STREAM_RST_INVALID_ACK,
    },
    {
            "stream.pkt_retransmission",
            STREAM_PKT_RETRANSMISSION,
    },
    {
            "stream.pkt_spurious_retransmission",
            STREAM_PKT_SPURIOUS_RETRANSMISSION,
    },
    {
            "stream.pkt_bad_window_update",
            STREAM_PKT_BAD_WINDOW_UPDATE,
    },

    {
            "stream.suspected_rst_inject",
            STREAM_SUSPECTED_RST_INJECT,
    },
    {
            "stream.wrong_thread",
            STREAM_WRONG_THREAD,
    },

    {
            "stream.reassembly_segment_before_base_seq",
            STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ,
    },
    {
            "stream.reassembly_no_segment",
            STREAM_REASSEMBLY_NO_SEGMENT,
    },
    {
            "stream.reassembly_seq_gap",
            STREAM_REASSEMBLY_SEQ_GAP,
    },
    {
            "stream.reassembly_overlap_different_data",
            STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA,
    },

    { NULL, 0 },
};
