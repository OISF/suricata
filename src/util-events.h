/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 */

#ifndef __UTIL_EVENTS_H__
#define __UTIL_EVENTS_H__

#include <stdint.h>

#include "htp/bstr.h"

/* Maximum number of HTTP headers allowed per event per direction. */
#define MAX_NUM_HTTP_HEADERS 100
#define TIMESTAMP_LEN        64
#define PACKET_ALERT_MAX 15 /* As defined in decode.h. */

/* Struct representing fields common to all callbacks (5-tuple, timestamp...). */
typedef struct {
    /* Packet source IP */
    const char *src_ip;
    /* Packet dest IP */
    const char *dst_ip;
    /* Packet source port */
    uint16_t sp;
    /* Packet dest IP */
    uint16_t dp;
    /* Transport layer protocol */
    const char *proto;
    /* App layer protocol */
    const char *app_proto;
    const char *app_proto_ts;
    const char *app_proto_tc;
    /* Original application level protocol. Used to indicate the previous protocol when changing
     * to another protocol. */
    const char *app_proto_orig;
    /* Expected app protocol: used in protocol change/upgrade. */
    const char *app_proto_expected;
    /* Packet direction */
    const char *direction;
    /* Timestamp */
    char timestamp[TIMESTAMP_LEN];
    /* Flow id */
    int64_t flow_id;
    /* Parent id */
    int64_t parent_id;
    /* Input interface */
    const char *dev;
    /* Vland ids */
    uint16_t vlan_id[2];
    /* ICMP types and codes. */
    int8_t icmp_type;
    int8_t icmp_code;
    int8_t icmp_response_type;
    int8_t icmp_response_code;
    /* XFF info */
    const char *xff;
} Common;

/* Struct representing an HTTP header. */
typedef struct HttpHeader {
    bstr *name;
    bstr *value;
} HttpHeader;

/* Struct representing an Http transactions. Included in variious events. */
typedef struct HttpInfo {
    /* Transaction id, for correlation with other events */
    int tx_id;
    /* Hostname */
    bstr *hostname;
    /* Method */
    bstr *http_method;
    /* Protocol */
    bstr *protocol;
    /* Port */
    int http_port;
    /* Uri */
    bstr *uri;
    /* User agent */
    bstr *user_agent;
    /* Xff header */
    bstr *xff;
    /* Content-Type header */
    bstr *content_type;
    /* Content-Range header (raw and parsed) */
    bstr *content_range_raw;
    int64_t content_range_start;
    int64_t content_range_end;
    int64_t content_range_size;
    /* Redirect (location header) */
    bstr *redirect;
    /* Referer */
    bstr *referer;
    /* Direction */
    const char *direction;
    /* Response message length. */
    uint64_t response_len;
    /* Response status. */
    uint64_t status;
    /* Request headers. */
    HttpHeader request_headers[MAX_NUM_HTTP_HEADERS];
    /* Response headers. */
    HttpHeader response_headers[MAX_NUM_HTTP_HEADERS];
} HttpInfo;

/* App layer event information included in alerts and fileinfo events. */
typedef union AppLayer {
    HttpInfo *http;
    void *nta; /* JsonBuilder object but avoid including rust.h */
} AppLayer;

/* Ip port information reported in alerts `source` and `target` fields. */
typedef struct IpPort {
    const char *ip;
    uint16_t port;
} IpPort;

/* Struct representing a single alert. */
typedef struct Alert{
    /* Action for this alert */
    const char *action;
    /* Signature relevant fields */
    uint32_t sid;
    uint32_t gid;
    uint32_t rev;
    int severity;
    const char *msg;
    const char *category;
    const char *metadata;
    /* Source and target. */
    IpPort source;
    IpPort target;
    /* Transaction id, for correlation with other events */
    int tx_id;
    /* Tenant id (suricata) */
    uint32_t tenant_id_suri;
} Alert;

/* Struct representing a single flow. */
typedef struct FlowInfo {
    /* Counters */
    uint32_t pkts_toserver;
    uint32_t pkts_toclient;
    uint64_t bytes_toserver;
    uint64_t bytes_toclient;
    /* Timestamps */
    char start[TIMESTAMP_LEN];
    char end[TIMESTAMP_LEN];
    /* Age */
    int32_t age;
    /* Emergency flag */
    uint8_t emergency;
    /* State */
    const char *state;
    /* Reason */
    const char *reason;
    /* If flow has alerts */
    int alerted;

    /* TCP flags. */
    struct {
        /* TCP packet flags (hex). */
        char tcp_flags[3];
        /* TCP to server flags (hex). */
        char tcp_flags_ts[3];
        /* TCP to client flags (hex). */
        char tcp_flags_tc[3];
        /* TCP flags as single values (true/false). */
        uint8_t syn;
        uint8_t fin;
        uint8_t rst;
        uint8_t psh;
        uint8_t ack;
        uint8_t urg;
        uint8_t ecn;
        uint8_t cwr;
        /* TCP state .*/
        const char *state;
    } tcp;
} FlowInfo;

/* Struct representing an alert event. It will be passed along in the callback. */
typedef struct AlertEvent {
    Common common;
    FlowInfo flow;
    Alert alert;

    /* App layer event information, if any */
    AppLayer app_layer;
} AlertEvent;

/* Struct representing a fileinfo event. It will be passed along in the callback. */
typedef struct FileinfoEvent {
    Common common;

    struct {
        /* File name */
        const uint8_t *filename;
        /* File name len. */
        uint16_t filename_len;
        /* Signature id of a rule that triggered the filestore event. */
        uint32_t *sids;
        uint32_t sid_cnt;
        /* Magic, if any */
        const char *magic;
        /* If the file has gaps */
        int gaps;
        /* File state at the moment of logging */
        const char *state;
        /* File MD5, if supported */
        const char *md5;
        /* File SHA1, if supported */
        const char *sha1;
        /* File SHA256, if supported */
        const char *sha256;
        /* If the file is stored on disk */
        int stored;
        /* File id for a stored file */
        uint32_t file_id;
        /* File size */
        uint64_t size;
        /* File start */
        uint64_t start;
        /* File end */
        uint64_t end;
        /* Transaction id, for correlation with other events */
        int tx_id;
    } fileinfo;

    /* App layer event information, if any */
    AppLayer app_layer;
} FileinfoEvent;


/* Struct representing a flow event. It will be passed along in the callback. */
typedef struct FlowEvent {
    Common common;
    FlowInfo flow;
} FlowEvent;

/* Struct representing a flow snip event. It will be passed along in the callback. */
typedef struct FlowSnipEvent {
    Common common;
    FlowInfo flow;

    /* FlowSnip id */
    uint32_t snip_id;
    /* Number of packets in the pcap */
    uint16_t num_packets;
    /*Counter of the first packet of the snip relative to the flow */
    uint16_t pkt_cnt;
    /* Timestamp of the first packet */
    char timestamp_first[TIMESTAMP_LEN];
    /* Timestamp of the last packet */
    char timestamp_last[TIMESTAMP_LEN];

    /* Array of alerts and corresponding size (<= PACKET_ALERT_MAX). */
    uint16_t alerts_size;
    Alert alerts[PACKET_ALERT_MAX];
} FlowSnipEvent;

/* Struct representing an Http event. It will be passed along in the callback. */
typedef struct HttpEvent {
    Common common;
    HttpInfo http;
} HttpEvent;

#endif /* __UTIL_EVENTS_H__ */
