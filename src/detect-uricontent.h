#ifndef __DETECT_URICONTENT_H__
#define __DETECT_URICONTENT_H__

#define DETECT_URICONTENT_NOCASE        0x01
#define DETECT_URICONTENT_DISTANCE      0x02
#define DETECT_URICONTENT_WITHIN        0x04

#define DETECT_URICONTENT_DISTANCE_NEXT 0x08
#define DETECT_URICONTENT_WITHIN_NEXT   0x10

#define DETECT_URICONTENT_RAWBYTES      0x20

typedef struct DetectUricontentData_ {
    uint8_t *uricontent;
    uint8_t uricontent_len;
    uint32_t id;

    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    uint8_t flags;
} DetectUricontentData;

/* prototypes */
void DetectUricontentRegister (void);
uint32_t DetectUricontentMaxId(DetectEngineCtx *);
void PktHttpUriFree(Packet *p);

#endif /* __DETECT_URICONTENT_H__ */

