/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Common utilities for event callbacks.
 *
 */

#include "output-callback.h"

void EventAddCommonInfo(const Packet *p, enum OutputJsonLogDirection dir, Common *common)
{
    /* First initialize the address info (5-tuple). */
    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);
    common->src_ip = addr.src_ip;
    common->dst_ip = addr.dst_ip;
    common->sp = addr.sp;
    common->dp = addr.dp;
    common->proto = addr.proto;

    /* Timestamp. */
    CreateIsoTimeString(p->ts, common->timestamp, sizeof(common->timestamp));

    /* Direction. */
    const char *direction = NULL;
    switch (dir) {
        case LOG_DIR_PACKET:
            if ((PKT_IS_TOCLIENT(p))) {
                direction = OUTPUT_DIR_PACKET_FLOW_TOCLIENT;
            } else {
                direction = OUTPUT_DIR_PACKET_FLOW_TOSERVER;
            }
            break;
        case LOG_DIR_FLOW:
        case LOG_DIR_FLOW_TOSERVER:
            direction = OUTPUT_DIR_PACKET_FLOW_TOSERVER;
            break;
        case LOG_DIR_FLOW_TOCLIENT:
            direction = OUTPUT_DIR_PACKET_FLOW_TOCLIENT;
            break;
        default:
            direction = "";
            break;
    }
    common->direction = direction;

    /* App layer protocol, if any. */
    if (p->flow != NULL) {
        const AppProto app_proto = FlowGetAppProtocol(p->flow);
        common->app_proto = app_proto ? AppProtoToString(app_proto) : "";
    }
}