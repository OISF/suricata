#include "suricata-common.h"
#include "detect.h"

#include "app-layer-protos.h"

/** detection engine will be grouped:
 *  - app layer protocol
 *  - flow direction
 *  - phase
 *  - src ip/dst ip
 *  - ports? (maybe unnecessary as proto detection is in place)
 */

#define AL_DETECT_FLOW_PHASES 4

typedef struct AlDetectProto_ {
    DetectAddressGroupsHead *src[AL_DETECT_FLOW_PHASES];
    DetectAddressGroupsHead *tmp[AL_DETECT_FLOW_PHASES];
} AlDetectProto;

/** 2 flow states: to_client, to_server */
#define AL_DETECT_FLOW_STATES 2

typedef struct AlDetectFlow_ {
    AlDetectProto *proto[ALPROTO_MAX];
} AlDetectFlow;

typedef struct AlDetectEngineCtx_ {
    /* flow direction */
    AlDetectFlow *flow[AL_DETECT_FLOW_STATES];

} AlDetectEngineCtx;

