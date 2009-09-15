/** Copyright (c) 2009 Open Information Security Foundation
 *
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __ALERT_UNIFIED2_ALERT_H__
#define __ALERT_UNIFIED2_ALERT_H__

#define UNIFIED2_PACKET_FLAG 1
#define UNIFIED2_BLOCKED_FLAG 0x20

#define UNIFIED2_EVENT_TYPE 1
#define UNIFIED2_PACKET_TYPE 2
#define UNIFIED2_IDS_EVENT_TYPE 7
#define UNIFIED2_EVENT_EXTENDED_TYPE 66
#define UNIFIED2_PERFORMANCE_TYPE 67
#define UNIFIED2_PORTSCAN_TYPE 68
#define UNIFIED2_IDS_EVENT_IPV6_TYPE 72
#define UNIFIED2_IDS_EVENT_MPLS_TYPE 99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS_TYPE 100

int Unified2Alert (ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2AlertThreadInit(ThreadVars *, void *, void **);
int Unified2AlertThreadDeinit(ThreadVars *, void *);
int Unified2IPv4TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2IPv6TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2PacketTypeAlert(ThreadVars *, Packet *, void *);

void Unified2RegisterTests();
void TmModuleUnified2AlertRegister (void);

typedef struct Unified2AlertThread_ {
    FILE *fp;
    uint32_t size_limit;
    uint32_t size_current;
} Unified2AlertThread;

typedef struct Unified2AlertFileHeader_ {
    uint32_t type;
    uint32_t length;
} Unified2AlertFileHeader;

typedef struct AlertIPv4Unified2_ {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sp;
    uint16_t dp;
    uint8_t  protocol;
    uint8_t  packet_action;
} AlertIPv4Unified2;

typedef struct AlertIPv6Unified2_ {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    uint16_t sp;
    uint16_t dp;
    uint8_t  protocol;
    uint8_t  packet_action;
} AlertIPv6Unified2;

typedef struct AlertUnified2Packet_ {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
} Unified2Packet;

#endif /* __ALERT_UNIFIED2_ALERT_H__ */

