#ifndef __UTIL_SPM_BS__
#define __UTIL_SPM_BS__

#include "suricata-common.h"
#include "suricata.h"

uint8_t *BasicSearch(const uint8_t *, uint32_t, const uint8_t *, uint32_t);
uint8_t *BasicSearchNocase(const uint8_t *, uint32_t, const uint8_t *, uint32_t);
void BasicSearchInit (void);

#endif /* __UTIL_SPM_BS__ */

