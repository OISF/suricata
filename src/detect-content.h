#ifndef __DETECT_CONTENT_H__
#define __DETECT_CONTENT_H__

#define DETECT_CONTENT_NOCASE        0x01
#define DETECT_CONTENT_DISTANCE      0x02
#define DETECT_CONTENT_WITHIN        0x04

#define DETECT_CONTENT_DISTANCE_NEXT 0x08
#define DETECT_CONTENT_WITHIN_NEXT   0x10

#define DETECT_CONTENT_RAWBYTES      0x20

typedef struct DetectContentData_ {
    uint8_t *content;
    uint8_t content_len;
    uint32_t id;

    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    uint8_t flags;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse (char *contentstr);
void DetectContentFree(void *);

#endif /* __DETECT_CONTENT_H__ */

