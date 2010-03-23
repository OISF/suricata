/** Copyright (c) 2009 Open Information Security Foundation */

#ifndef __UTIL_SPM_H__
#define __UTIL_SPM_H__

#include "util-spm-bs.h"
#include "util-spm-bs2bm.h"
#include "util-spm-bm.h"

/** Default algorithm to use: Boyer Moore */
inline uint8_t *Bs2bmSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint32_t needlelen);
inline uint8_t *Bs2bmNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint32_t needlelen);
inline uint8_t *BoyerMooreSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint32_t needlelen);
inline uint8_t *BoyerMooreNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint32_t needlelen);

/* Macros for automatic algorithm selection (use them only when you can't store the context) */
#define SpmSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreSearch(text, textlen, needle, needlelen); \
    mfound; \
    })

#define SpmNocaseSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreNocaseSearch(text, textlen, needle, needlelen); \
    mfound; \
    })

void UtilSpmSearchRegistertests(void);
#endif /* __UTIL_SPM_H__ */
