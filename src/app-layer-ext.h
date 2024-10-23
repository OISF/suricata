#ifndef SURICATA_APP_LAYER_EXT_H
#define SURICATA_APP_LAYER_EXT_H

#include <stdint.h>

typedef enum AppLayerEventType {
    APP_LAYER_EVENT_TYPE_TRANSACTION = 1,
    APP_LAYER_EVENT_TYPE_PACKET = 2,
} AppLayerEventType;

typedef int (*SCAppLayerStateGetProgressFn)(void *alstate, uint8_t direction);
typedef int (*SCAppLayerStateGetEventInfoFn)(
        const char *event_name, int *event_id, AppLayerEventType *event_type);
typedef int (*SCAppLayerStateGetEventInfoByIdFn)(
        int event_id, const char **event_name, AppLayerEventType *event_type);

#endif /* SURICATA_APP_LAYER_EXT_H */
