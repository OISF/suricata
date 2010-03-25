/** Copyright (c) 2009 Open Information Security Foundation
 *
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __ALERT_UNIFIED2_ALERT_H__
#define __ALERT_UNIFIED2_ALERT_H__

/** Unified2 Option packet action */
#define UNIFIED2_PACKET_FLAG 1
#define UNIFIED2_BLOCKED_FLAG 0x20

/** Unified2 Header Types */
#define UNIFIED2_EVENT_TYPE 1
#define UNIFIED2_PACKET_TYPE 2
#define UNIFIED2_IDS_EVENT_TYPE 7
#define UNIFIED2_EVENT_EXTENDED_TYPE 66
#define UNIFIED2_PERFORMANCE_TYPE 67
#define UNIFIED2_PORTSCAN_TYPE 68
#define UNIFIED2_IDS_EVENT_IPV6_TYPE 72
#define UNIFIED2_IDS_EVENT_MPLS_TYPE 99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS_TYPE 100

void TmModuleUnified2AlertRegister (void);
OutputCtx *Unified2AlertInitCtx(ConfNode *);

#endif /* __ALERT_UNIFIED2_ALERT_H__ */

