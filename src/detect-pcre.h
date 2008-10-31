#ifndef __DETECT_PCRE_H__
#define __DETECT_PCRE_H__

#define DETECT_PCRE_DISTANCE      0x0001
#define DETECT_PCRE_WITHIN        0x0002
#define DETECT_PCRE_RELATIVE      0x0004

#define DETECT_PCRE_DISTANCE_NEXT 0x0008
#define DETECT_PCRE_WITHIN_NEXT   0x0010

#define DETECT_PCRE_RAWBYTES      0x0020
#define DETECT_PCRE_URI           0x0040

#define DETECT_PCRE_CAPTURE_PKT   0x0080
#define DETECT_PCRE_CAPTURE_FLOW  0x0100

typedef struct _DetectPcreData {
    /* pcre options */
    pcre *re;
    pcre_extra *sd;
    int opts;

    /* match position vars */
    u_int16_t depth;
    u_int16_t offset;
    int32_t within;
    int32_t distance;

    u_int16_t flags;

    char *capname;
} DetectPcreData;

/* prototypes */
void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

