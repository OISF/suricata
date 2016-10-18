/*
 * cmcommon.h
 *
 *  Created on : Jun 1, 2015
 *  Author     : root
 */

/** @file cmcommon.h
 *  @brief structures to type cast for Application stats
 */
#ifndef _DPDK_GLUE_CMCOMMON_
#define _DPDK_GLUE_CMCOMMON_
     
/* I N C L U D E S */
#include <stdio.h>
#include <stdint.h>

/* D E F I N E */
#define MSG(m, ...) fprintf(stderr, "\n %s %d - " m " \n", __func__, __LINE__, ##__VA_ARGS__)

/* E N U M E R A T I O N S */
//! Error enums
typedef enum xsStatusCode_t
{
    XS_SUCCESS = 0,      //!< Success
    XS_CONFIGURED,       //!< Already Configured
    XS_ERROR_VALIDATION, //!< Failure in parameter validation
    XS_ERROR_PARAMS,     //!< Undefined Parameter
    XS_UNKNOWN_INPUT,    //!< Null value
    XS_UNKNOWN_PARAM,    //!< Unknown parameter
    XS_INVALID_IP,       //!< Invalide IP address
    XS_INVALID_PORT,     //!< Invalid port number
    XS_INVALID_SRC_IP,   //!< Invalid Source IP address
    XS_INVALID_SRC_PORT, //!< Invalid Source port
    XS_INVALID_DEST_IP,  //!< Invalid destination IP address
    XS_INVALID_DEST_PORT,//!< Invalid destination port 
    XS_LIMIT_EXCEED,     //!< Maximum limit for rule count exceed
    XS_DROP_ENABLED,     //!< Drop mode enabled
    XS_IDS_MODE_ENABLED  //!< IDS mode enabled
} xsStatusCode;


//!Get Flow stats Information Structure .
/*! Gives Flow Manager Thread details
 */
typedef struct
{
    //! Flow Merger Closed Pruned
    uint64_t flow_mgr_closed_pruned;
    //! Flow Merger New Pruned
    uint64_t flow_mgr_new_pruned;
    //! Flow Merger New Pruned
    uint64_t flow_mgr_est_pruned;
    //! Flow Memuse
    uint64_t flow_memuse;
    //! Flow Spare
    uint64_t flow_spare;
    //! Flow Emerged Mode Entered
    uint64_t flow_emerg_mode_entered;
    //! Flow Emerged Mode Over
    uint64_t flow_emerg_mode_over;
} flow_stat_t;

//! Get Decoder stats Information Structure .
/*! Gives Information about 
 */
typedef struct 
{
    //! Decoder Packets
    uint64_t decoder_pkts;
    //! Decoder Bytes
    uint64_t decoder_bytes;
    //! Decoder Ipv4
    uint64_t decoder_ipv4;
    //! Decoder Ipv6
    uint64_t decoder_ipv6;
    //! Decoder Etrhernet
    uint64_t decoder_ethernet;
    //! Decoder Raw
    uint64_t decoder_raw;
    //! Decoder SLL
    uint64_t decoder_sll;
    //! Decoder TCP
    uint64_t decoder_tcp;
    //! Decoder UDP
    uint64_t decoder_udp;
    //! Decoder SCTP
    uint64_t decoder_sctp;
    //! Decoder ICMPV4
    uint64_t decoder_icmpv4;
    //! Decoder ICMPV6
    uint64_t decoder_icmpv6;
    //! Decoder PPP
    uint64_t decoder_ppp;
    //! Decoder PPPOE
    uint64_t decoder_pppoe;
    //! Decoder GRE
    uint64_t decoder_gre;
    //! Decoder VLAN
    uint64_t decoder_vlan;
    //! Average Packet Size
    uint64_t decoder_avg_pkt_size;
    //! Maximum Packet Size
    uint64_t decoder_max_pkt_size;
} decoder_stat_t;

//! Defrag stats Information Structure .
/*! GIves Information about ipv4 fragments, reassembled, timeouts etc
 */
typedef struct 
{
    //! Ipv4 Fragments
    uint64_t defrag_ipv4_fragments;
    //! Ipv4 Reassembled
    uint64_t defrag_ipv4_reassembled;
    //! Ipv4 Timeouts
    uint64_t defrag_ipv4_timeouts;
    //! Ipv6 Fragments
    uint64_t defrag_ipv6_fragments;
    //! Ipv6 Reassembled
    uint64_t defrag_ipv6_reassembled;
    //! Ipv6 Timeouts
    uint64_t defrag_ipv6_timeouts;
} defrag_stat_t;

//! Get TCP stats Information Structure 
/*! Gives information about TCP Connection status and Retransmission status
 */
typedef struct 
{
    //! TCP Sessions
    uint64_t tcp_sessions;
    //! TCP Sessions Memcap drop
    uint64_t tcp_ssn_memcap_drop;
    //! TCP Psuedo
    uint64_t tcp_pseudo;
    //! TCP invalid checksum
    uint64_t tcp_invalid_checksum;
    //! TCP no flow
    uint64_t tcp_no_flow;
    //! TCP reused scan
    uint64_t tcp_reused_ssn;
    //! TCP memuse
    uint64_t tcp_memuse;
    //! TCP SYN
    uint64_t tcp_syn;
    //! TCP SYUNACK 
    uint64_t tcp_synack;
    //! TCP RST
    uint64_t tcp_rst;
    //! TCP saegment memcap drop
    uint64_t tcp_segment_memcap_drop;
    //! TCP stream depth reached
    uint64_t tcp_stream_depth_reached;
    //! TCP reassembly memuse
    uint64_t tcp_reassembly_memuse;
    //! TCP reassembly 
    uint64_t tcp_reassembly_gap;
} tcp_stat_t;

//!Detect stats Information Structure 
/*! GIves INformation about detect alerts
 */
typedef struct 
{
    //! Detect Alert
    uint64_t detect_alert;
}detect_stat_t;

//! Get Frame stats Information Structure 
/*!
  Gives information about packets received and sent, ethernet bytes ,icmp packets etc
*/

typedef struct 
{
    //! ipv4 fragments
    uint64_t ipv4_frag;
     //! ipv6 fragments
    uint64_t ipv6_frag;
     //! Recieve packets
    uint64_t rx_pkt;
     //! Transmit packets
    uint64_t tx_pkt;
     //! Recieve Byte
    uint64_t rx_byte;
     //! Transmit Bytes
    uint64_t tx_byte;
     //! Transmit Error
    uint64_t rx_err;
     //! Transmit Error
    uint64_t tx_err;
     //! Ethernet Count
    uint64_t eth_cnt;
     //! ipv4 Count
    uint64_t ipv4_cnt;
     //! ipv6 Count
    uint64_t ipv6_cnt;
     //! tcp Count
    uint64_t tcp_cnt;
     //! http Count
    uint64_t http_cnt;
     //! http data
    uint64_t http_data;
     //! udp Count
    uint64_t udp_cnt;
     //! icmp Count
    uint64_t icmp_cnt;
     //! arp Count
    uint64_t arp_cnt;
     //! ftp Count
    uint64_t ftp_cnt;
     //! Checksum Error
    uint64_t checksum_Err;
} frame_stat_t;


//! Get Stats Information Structure 
/*!
  Gives information about packets received and sent, ethernet bytes ,icmp packets etc for RX core
*/
typedef struct 
{
     //! Received Packets
     uint64_t  rx_pkt;
     //! Received Byte
     uint64_t  rx_byte;
     //! ipv4 packets
     uint64_t  ipv4;
     //! ipv6 packets
     uint64_t  ipv6;
     //! tcp packets
     uint64_t  tcp;
     //! udp packets
     uint64_t  udp;
     //! icmp packets
     uint64_t  icmp;
     //! ssl packets
     uint64_t  ssl;
     //! tls packets
     uint64_t  tls;
     //! gtp packets
     uint64_t  gtp;
     //! smp packets
     uint64_t  smp;
     //! ipv4 packets
     uint64_t  ftp;
     //! ipv4 packets
     uint64_t  smtp;
     //! ipv4 packets
     uint64_t  sctp;
     //! ipv4 packets
     uint64_t  dns;
     //! ipv4 packets
     uint64_t  http;
     //! ipv4 packets
     uint64_t  gre;
     //! ipv4 packets
     uint64_t  dcerpc;
     //! Transmitted Packets
     uint64_t  tx_pkt;
     //! ransmitted Byte
     uint64_t  tx_byte;
     //! Packet Drop
     uint64_t  pkt_drop;
     //! Failed 
     uint64_t  failed;
} rxfp_stats_t;


//! Get Application Stats Information Structure 
/*! 
   Gives information about acl matches found, packets processed etc fot  ST1
 */
typedef struct 
{
    //! Received Packets
    uint64_t  rx_pkt;
    //! Processed Packets
    uint64_t  rx_processed;
    //! ACL lookups received
    uint64_t  acl_lookup;
    //! ACL matches found
    uint64_t  acl_match;
    //! No ACL matches
    uint64_t  acl_nomatch;
    //! Packets Failed
    uint64_t  failed;
    //! Transmitted Packets
    uint64_t  tx_pkts;
} st_stats_t;


//! Get Application Stats Information Structure 
/*! 
   Gives information about acl matches found, packets processed etc fot  ST2
 */
typedef struct 
{
    //! Received Packets
    uint64_t rx_pkt;
    //! Transmitted Packets
    uint64_t tx_pkt;
    //! Transmitted Bytes
    uint64_t tx_byte;
    //! Packets Failed
    uint64_t failed;
    //! Error
    uint64_t Err;
} txfw_stats_t;

//! CP Rule Tuple Information structure.
/*! Gives Source port and Destination ports details, Protocol, Direction etc
 */
typedef struct 
{
    //! Flow Direction
    uint8_t rFlow;
    //! Protocol
    uint8_t rProto;
    //! Source Port
    uint16_t rSrcPort;
    //! Destination port
    uint16_t rDstPort;
    //! Result Index
    uint16_t rIndex;
    //! Source Ip Address
    uint32_t rSrcIp;
    //! Destination Ip Address
    uint32_t rDstIp;
} rule_ipv4Tuple_t;

//! CP Result Information structure.
/*! Gives Information about Action Counters etc
 */
typedef struct 
{
    //! Action specified for rule
    uint8_t rAction;
    //! Reserved bits
    uint8_t rsrved[7];
    //! Counter
    uint64_t rCounter;
} rule_ipv4Result_t;

//! Stats to check for DPDK frame protocol or app match  
/*! 
    Maintians pre-process Match stats, which allows DPDK RX core to choose for
    rule-pattern matching.
 */
typedef struct 
{
    //! protocl as ipv4
    uint64_t ipv4;
    //! protocl as ipv6
    uint64_t ipv6;
    //! protocl as tcp
    uint64_t tcp;
    //! protocl as udp
    uint64_t udp;
    //! protocl as sctp
    uint64_t sctp;
    //! protocl as icmpv4
    uint64_t icmpv4;
    //! protocl as icmpv6
    uint64_t icmpv6;
    //! application as gre
    uint64_t gre;
    //! packet as ethernet
    uint64_t ethernet;
    //! packet as ppp
    uint64_t ppp;
    //! packet as ppoe
    uint64_t pppoe;
    //! packet as raw
    uint64_t raw;
    //! packet as sll
    uint64_t sll;
    //! packet as valn
    uint64_t vlan;
    //! packet as qinq
    uint64_t qinq;
    //! application as http
    uint64_t http;
    //! application as ssl
    uint64_t ssl;
    //! application as tls
    uint64_t tls;
    //! application as smb
    uint64_t smb;
    //! application as smb2
    uint64_t smb2;
    //! application as dcerpc
    uint64_t dcerpc;
    //! application as smtp
    uint64_t smtp;
    //! application as ftp
    uint64_t ftp;
    //! application as ssh
    uint64_t ssh;
    //! application as dns
    uint64_t dns;
    //! total rule count 
    uint64_t totalRules;
} stats_matchPattern_t;

//! Stats to debug DPDK-SURICATA frame processing
/*! 
    Maintians per interface stats
 */
typedef struct 
{
    //! Received Packets
    uint64_t  rx_pkt;
    //! Received Bytes
    uint64_t rx_bytes;
    //! Received Error
    uint64_t rx_err;
    //! Received Packets
    uint64_t  processed;
    //! ACL lookups received
    uint64_t  acl_lookup;
    //! Transmitted Packets
    uint64_t  tx_pkt;
    //! Transmitted Bytes
    uint64_t tx_bytes;
    //! Transmit Error
    uint64_t tx_err;
    //! Checksum Error
    uint64_t checksum_Err;
    //! ipv4 fragments
    uint64_t ipv4_frag;
     //! ipv6 fragments
    uint64_t ipv6_frag;
     //! Ethernet Count
    uint64_t eth_cnt;
     //! ipv4 Count
    uint64_t ipv4_cnt;
     //! ipv6 Count
    uint64_t ipv6_cnt;
     //! tcp Count
    uint64_t tcp_cnt;
     //! udp Count
    uint64_t udp_cnt;
     //! icmp Count
    uint64_t icmp_cnt;
     //! arp Count
    uint64_t arp_cnt;
} debug_dpdkSuricata_t;

typedef struct
{
     //! Tx Error
    uint64_t tx_err;
     //! Ring Full
    uint64_t ring_full;
     //! Enqueue Error
    uint64_t enq_err;
     //! Packet Null
    uint64_t sc_pkt_null;
    //! Suricata Process Fail
    uint64_t sc_fail;
}dpdkFrameStats_t;

#endif /* _DPDK_GLUE_CMCOMMON_ */

