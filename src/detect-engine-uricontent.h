#ifndef __DETECT_ENGINE_URICONTENT_H__
#define __DETECT_ENGINE_URICONTENT_H__

int DetectEngineInspectPacketUris(DetectEngineCtx *,
        DetectEngineThreadCtx *, Signature *, Flow *, uint8_t,
        void *, Packet *);

#endif /* __DETECT_ENGINE_URICONTENT_H__ */

