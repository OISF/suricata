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
    /* Packet direction */
    const char *direction;
    /* Timestamp */
    char timestamp[TIMESTAMP_LEN];
} Common;

/* Struct representing an HTTP header. */
typedef struct HttpHeader {
    bstr *name;
    bstr *value;
} HttpHeader;

/* Struct representing an Http transactions. Included in variious events. */
typedef struct HttpInfo {
    /* Transaction id, for correlation with other events */
    uint64_t tx_id;
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
    /* Redirect (location header) */
    bstr *redirect;
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
typedef union app_layer {
    HttpInfo *http;
    void *nta; /* JsonBuilder object but avoid including rust.h */
} app_layer;

/* Struct representing an alert event. It will be passed along in the callback. */
typedef struct AlertEvent {
    Common common;

    struct {
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
        /* Tenant id (suricata) */
        uint32_t tenant_id_suri;
    } alert;

    /* App layer event information, if any */
    app_layer app_layer;
} AlertEvent;

/* Struct representing a fileinfo event. It will be passed along in the callback. */
typedef struct FileinfoEvent {
    Common common;

    struct {
        /* File name */
        const uint8_t *filename;
        /* File name len. */
        uint16_t filename_len;
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
        uint64_t tx_id;
    } fileinfo;

    /* App layer event information, if any */
    app_layer app_layer;
} FileinfoEvent;

/* Struct representing a flow event. It will be passed along in the callback. */
typedef struct FlowEvent {
    Common common;

    struct {
        /* Flow id */
        int64_t flow_id;
        /* Parent id */
        int64_t parent_id;
        /* Input interface */
        const char *dev;
        /* Vland ids */
        uint16_t vlan_id[2];
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
    } flow;
} FlowEvent;

/* Struct representing an Http event. It will be passed along in the callback. */
typedef struct HttpEvent {
    Common common;

    HttpInfo http;
} HttpEvent;

#endif /* __UTIL_EVENTS_H__ */
