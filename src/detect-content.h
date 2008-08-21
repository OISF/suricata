#ifndef __DETECT_CONTENT_H__
#define __DETECT_CONTENT_H__

#define DETECT_CONTENT_NOCASE        0x01
#define DETECT_CONTENT_DISTANCE      0x02
#define DETECT_CONTENT_WITHIN        0x04

#define DETECT_CONTENT_DISTANCE_NEXT 0x08
#define DETECT_CONTENT_WITHIN_NEXT   0x10

#define DETECT_CONTENT_RAWBYTES      0x20


typedef struct _DetectContentData {
    u_int8_t *content;
    u_int8_t content_len;
    u_int32_t id;

    u_int16_t depth;
    u_int16_t offset;
    int32_t distance;
    int32_t within;
    u_int8_t flags;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
u_int32_t DetectContentMaxId(void);

#endif /* __DETECT_CONTENT_H__ */

