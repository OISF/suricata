#ifndef __DETECT_ENGINE_PAYLOAD_H__
#define __DETECT_ENGINE_PAYLOAD_H__

int DetectEngineInspectPacketPayload(DetectEngineCtx *,
        DetectEngineThreadCtx *, Signature *, Flow *, uint8_t,
        void *, Packet *);

void PayloadRegisterTests(void);

#endif /* __DETECT_ENGINE_PAYLOAD_H__ */

