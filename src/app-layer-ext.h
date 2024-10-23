#ifndef SURICATA_APP_LAYER_EXT_H
#define SURICATA_APP_LAYER_EXT_H

#include <stdint.h>

typedef int (*SCAppLayerStateGetProgressFn)(void *alstate, uint8_t direction);

#endif /* SURICATA_APP_LAYER_EXT_H */
