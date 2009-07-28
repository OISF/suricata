#ifndef __DETECT_URICONTENT_H__
#define __DETECT_URICONTENT_H__

#define DETECT_URICONTENT_NOCASE        0x01
#define DETECT_URICONTENT_DISTANCE      0x02
#define DETECT_URICONTENT_WITHIN        0x04

#define DETECT_URICONTENT_DISTANCE_NEXT 0x08
#define DETECT_URICONTENT_WITHIN_NEXT   0x10

#define DETECT_URICONTENT_RAWBYTES      0x20

typedef struct DetectUricontentData_ {
    u_int8_t *uricontent;
    u_int8_t uricontent_len;
    u_int32_t id;

    u_int16_t depth;
    u_int16_t offset;
    int32_t distance;
    int32_t within;
    u_int8_t flags;
} DetectUricontentData;

/* prototypes */
void DetectUricontentRegister (void);
u_int32_t DetectUricontentMaxId(DetectEngineCtx *);

#endif /* __DETECT_URICONTENT_H__ */

