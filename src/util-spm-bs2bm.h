#ifndef __UTIL_SPM_BS2BM__
#define __UTIL_SPM_BS2BM__

#include "suricata-common.h"
#include "suricata.h"

#define ALPHABET_SIZE 256

inline void Bs2BmBadchars(const uint8_t *, uint32_t, uint8_t *);
inline void Bs2BmBadcharsNocase(const uint8_t *, uint32_t, uint8_t *);
inline uint8_t * Bs2Bm(const uint8_t *, uint32_t, const uint8_t *, uint32_t, uint8_t []);
inline uint8_t *Bs2BmNocase(const uint8_t *, uint32_t, const uint8_t *, uint32_t, uint8_t []);

#endif /* __UTIL_SPM_BS2BM__ */

