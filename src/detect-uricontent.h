#ifndef __DETECT_URICONTENT_H__
#define __DETECT_URICONTENT_H__

#define DETECT_URICONTENT_NOCASE        0x01
#define DETECT_URICONTENT_DISTANCE      0x02
#define DETECT_URICONTENT_WITHIN        0x04

#define DETECT_URICONTENT_DISTANCE_NEXT 0x08
#define DETECT_URICONTENT_WITHIN_NEXT   0x10

#define DETECT_URICONTENT_RAWBYTES      0x20
#define DETECT_URICONTENT_NEGATED       0x40
#define DETECT_URICONTENT_RELATIVE_NEXT 0x80

#define DETECT_URICONTENT_IS_SINGLE(c) (!((c)->flags & DETECT_URICONTENT_DISTANCE || \
                                       (c)->flags & DETECT_URICONTENT_WITHIN || \
                                       (c)->flags & DETECT_URICONTENT_RELATIVE || \
                                       (c)->depth > 0 || \
                                       (c)->within > 0))

#include "util-spm-bm.h"

typedef struct DetectUricontentData_ {
    uint8_t *uricontent;
    uint8_t uricontent_len;
    uint32_t id;

    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    uint8_t flags;

    BmCtx *bm_ctx;     /**< Boyer Moore context (for spm search) */

} DetectUricontentData;

/* prototypes */
void DetectUricontentRegister (void);
uint32_t DetectUricontentMaxId(DetectEngineCtx *);
uint32_t DetectUricontentInspectMpm(ThreadVars *th_v, DetectEngineThreadCtx *det_ctx, void *alstate);
SigMatch *DetectUricontentGetLastPattern(SigMatch *);
void DetectUricontentPrint(DetectUricontentData *);

#endif /* __DETECT_URICONTENT_H__ */

