#ifndef __APP_LAYER_DETECT_PROTO_H__
#define __APP_LAYER_DETECT_PROTO_H__

void *AppLayerDetectProtoThread(void *td);

void AppLayerDetectProtoThreadInit(void);

void AppLayerDetectProtoThreadSpawn(void);
void AlpDetectRegisterTests(void);

#endif /* __APP_LAYER_DETECT_PROTO_H__ */

