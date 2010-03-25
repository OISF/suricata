#ifndef __UTIL_SPM_BM__
#define __UTIL_SPM_BM__

#include "suricata-common.h"
#include "suricata.h"

#define ALPHABET_SIZE 256

/* Context for booyer moore */
typedef struct BmCtx_ {
    int32_t bmBc[ALPHABET_SIZE];
    int32_t *bmGs; // = SCMalloc(sizeof(int32_t)*(needlelen + 1));
}BmCtx;

/** Prepare and return a Boyer Moore context */
BmCtx *BoyerMooreCtxInit(uint8_t *needle, uint32_t needle_len);

inline void PreBmBc(const uint8_t *x, int32_t m, int32_t *bmBc);
inline void BoyerMooreSuffixes(const uint8_t *x, int32_t m, int32_t *suff);
inline void PreBmGs(const uint8_t *x, int32_t m, int32_t *bmGs);
inline uint8_t *BoyerMoore(uint8_t *x, int32_t m, uint8_t *y, int32_t n, int32_t *bmGs, int32_t *bmBc);
inline void PreBmBcNocase(const uint8_t *x, int32_t m, int32_t *bmBc);
inline void BoyerMooreSuffixesNocase(const uint8_t *x, int32_t m, int32_t *suff);
inline void PreBmGsNocase(const uint8_t *x, int32_t m, int32_t *bmGs);
inline uint8_t *BoyerMooreNocase(uint8_t *x, int32_t m, uint8_t *y, int32_t n, int32_t *bmGs, int32_t *bmBc);

#endif /* __UTIL_SPM_BM__ */

