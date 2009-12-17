#ifndef __DETECT_CONTENT_H__
#define __DETECT_CONTENT_H__

#define DETECT_CONTENT_NOCASE            0x0001
#define DETECT_CONTENT_DISTANCE          0x0002
#define DETECT_CONTENT_WITHIN            0x0004

#define DETECT_CONTENT_FAST_PATTERN      0x0008
#define DETECT_CONTENT_DISTANCE_NEXT     0x0010
#define DETECT_CONTENT_WITHIN_NEXT       0x0020
#define DETECT_CONTENT_ISDATAAT_RELATIVE 0x0040

#define DETECT_CONTENT_RAWBYTES          0x0080

/** Set if the pattern is split into multiple chunks */
#define DETECT_CONTENT_IS_CHUNK          0x0100

/** Used for modifier propagations, to know if they are
 * yet updated or not */
#define CHUNK_UPDATED_DEPTH         0x01
#define CHUNK_UPDATED_OFFSET        0x02
#define CHUNK_UPDATED_ISDATAAT      0x04
#define CHUNK_UPDATED_DISTANCE      0x08
#define CHUNK_UPDATED_WITHIN        0x10

typedef struct DetectContentData_ {
    uint8_t *content;
    uint8_t content_len;
    uint32_t id;

    uint8_t negated;

    uint16_t depth;
    uint16_t offset;
    uint32_t isdataat;
    int32_t distance;
    int32_t within;
    uint16_t flags;

    /** The group this chunk belongs to, relative to the signature
     * It start from 1, and the last SigMatch of the list should be
     * also the total number of DetectContent "Real" Patterns loaded
     * from the Signature */
    uint8_t chunk_group_id;
    /** The id number for this chunk in the current group of chunks
     * Starts from 0, and a chunk with chunk_id == 0 should be the
     * of the current chunk group where real modifiers are set before
     * propagation */
    uint8_t chunk_id;
    /** For modifier propagations (the new flags) */
    uint8_t chunk_flags;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse (char *contentstr);

void DetectContentPrint(DetectContentData *);

/** This function search backwards the first applicable SigMatch holding
 * a DETECT_CONTENT context (If it belongs to a chunk group, the first chunk
 * of the group will be returned). Modifiers must call this */
SigMatch *DetectContentFindPrevApplicableSM(SigMatch *);

/** This function search forwards the first applicable SigMatch holding
 * a DETECT_CONTENT context. The Match process call this */
SigMatch *DetectContentFindNextApplicableSM(SigMatch *);

/** This function search backwards if we have a SigMatch holding
 * a Pattern before the SigMatch passed as argument */
SigMatch *DetectContentHasPrevSMPattern(SigMatch *);

/** After setting a new modifier, we should call one of the followings */
int DetectContentPropagateDepth(SigMatch *);
int DetectContentPropagateIsdataat(SigMatch *);
int DetectContentPropagateWithin(SigMatch *);
int DetectContentPropagateOffset(SigMatch *);
int DetectContentPropagateDistance(SigMatch *);
int DetectContentPropagateIsdataat(SigMatch *);

/** This shall not be called from outside detect-content.c (used internally)*/
int DetectContentPropagateModifiers(SigMatch *);

void DetectContentFree(void *);

#endif /* __DETECT_CONTENT_H__ */
