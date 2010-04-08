/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_H__
#define __FLOW_H__

#include "decode.h"
#include "util-var.h"

#define FLOW_QUIET      TRUE
#define FLOW_VERBOSE    FALSE

/* per flow flags */

/** At least on packet from the source address was seen */
#define FLOW_TO_SRC_SEEN            0x0001
/** At least on packet from the destination address was seen */
#define FLOW_TO_DST_SEEN            0x0002

/** Flow lives in the flow-state-NEW list */
#define FLOW_NEW_LIST               0x0004
/** Flow lives in the flow-state-EST (established) list */
#define FLOW_EST_LIST               0x0008
/** Flow lives in the flow-state-CLOSED list */
#define FLOW_CLOSED_LIST            0x0010

/** Flow was inspected against IP-Only sigs in the toserver direction */
#define FLOW_TOSERVER_IPONLY_SET    0x0020
/** Flow was inspected against IP-Only sigs in the toclient direction */
#define FLOW_TOCLIENT_IPONLY_SET    0x0040

/** Packet belonging to this flow should not be inspected at all */
#define FLOW_NOPACKET_INSPECTION    0x0080
/** Packet payloads belonging to this flow should not be inspected */
#define FLOW_NOPAYLOAD_INSPECTION   0x0100

/** All packets in this flow should be dropped */
#define FLOW_ACTION_DROP            0x0200

/* pkt flow flags */
#define FLOW_PKT_TOSERVER               0x01
#define FLOW_PKT_TOCLIENT               0x02
#define FLOW_PKT_ESTABLISHED            0x04
#define FLOW_PKT_STATELESS              0x08
#define FLOW_PKT_TOSERVER_IPONLY_SET    0x10
#define FLOW_PKT_TOCLIENT_IPONLY_SET    0x20
#define FLOW_PKT_NOSTREAM               0x40
#define FLOW_PKT_STREAMONLY             0x80

/* global flow config */
typedef struct FlowCnf_
{
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t max_flows;
    uint32_t memcap;
    uint32_t memuse;
    uint32_t prealloc;

    uint32_t timeout_new;
    uint32_t timeout_est;

    uint32_t emerg_timeout_new;
    uint32_t emerg_timeout_est;

} FlowConfig;

/* Hash key for the flow hash */
typedef struct FlowKey_
{
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint8_t recursion_level;

} FlowKey;

typedef struct Flow_
{
    Address src, dst;
    union {
        Port sp;        /**< tcp/udp source port */
        uint8_t type;   /**< icmp type */
    };
    union {
        Port dp;        /**< tcp/udp destination port */
        uint8_t code;   /**< icmp code */
    };
    uint8_t proto;
    uint8_t recursion_level;

    uint16_t flags;

    /* ts of flow init and last update */
    struct timeval startts;
    struct timeval lastts;

    /* pointer to the var list */
    GenericVar *flowvar;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t bytecnt;

    /** mapping to Flow's protocol specific protocols for timeouts
        and state and free functions. */
    uint8_t protomap;

    /** protocol specific data pointer, e.g. for TcpSession */
    void *protoctx;

    /** how many pkts and stream msgs are using the flow *right now* */
    uint16_t use_cnt;

    SCMutex m;

    /* list flow ptrs
     * NOTE!!! These are NOT protected by the
     * above mutex, but by the FlowQ's */
    struct Flow_ *hnext; /* hash list */
    struct Flow_ *hprev;
    struct Flow_ *lnext; /* list */
    struct Flow_ *lprev;

    struct FlowBucket_ *fb;
} Flow;

enum {
    FLOW_STATE_NEW = 0,
    FLOW_STATE_ESTABLISHED,
    FLOW_STATE_CLOSED,
};

typedef struct FlowProto_ {
    uint32_t new_timeout;
    uint32_t est_timeout;
    uint32_t closed_timeout;
    uint32_t emerg_new_timeout;
    uint32_t emerg_est_timeout;
    uint32_t emerg_closed_timeout;
    void (*Freefunc)(void *);
    int (*GetProtoState)(void *);
} FlowProto;

void FlowHandlePacket (ThreadVars *, Packet *);
void FlowInitConfig (char);
void FlowPrintQueueInfo (void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, char);
void FlowDecrUsecnt(ThreadVars *, Packet *);

void *FlowManagerThread(void *td);

void FlowManagerThreadSpawn(void);
void FlowRegisterTests (void);
int FlowSetProtoTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoFreeFunc (uint8_t , void (*Free)(void *));
int FlowSetFlowStateFunc (uint8_t , int (*GetProtoState)(void *));
void FlowUpdateQueue(Flow *);
void FlowLockSetNoPacketInspectionFlag(Flow *);
void FlowSetNoPacketInspectionFlag(Flow *);
void FlowLockSetNoPayloadInspectionFlag(Flow *);
void FlowSetNoPayloadInspectionFlag(Flow *);

#endif /* __FLOW_H__ */

