#ifndef __DETECT_ENGINE_ALERT_H__
#define __DETECT_ENGINE_ALERT_H__
#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

int PacketAlertReal(DetectEngineCtx *, DetectEngineThreadCtx *, Packet *);
int PacketAlertAppend(DetectEngineThreadCtx *, Signature *, Packet *);
int PacketAlertCheck(Packet *, uint32_t);
int PacketAlertRemove(Packet *, uint16_t);

#endif /* __DETECT_ENGINE_ALERT_H__ */
