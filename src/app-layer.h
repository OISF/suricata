#ifndef __APP_LAYER_H__
#define __APP_LAYER_H__

#include "flow.h"
#include "decode.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "stream.h"

uint16_t AppLayerGetProtoFromPacket(Packet *);
void *AppLayerGetProtoStateFromPacket(Packet *);
void *AppLayerGetProtoStateFromFlow(Flow *);

#endif /* __APP_LAYER_H__ */

