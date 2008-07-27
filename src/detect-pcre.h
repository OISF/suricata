#ifndef __DETECT_PCRE_H__
#define __DETECT_PCRE_H__

#define DETECT_PCRE_DISTANCE 0x01
#define DETECT_PCRE_WITHIN   0x02
#define DETECT_PCRE_RELATIVE 0x04

#define DETECT_PCRE_DISTANCE_NEXT 0x08
#define DETECT_PCRE_WITHIN_NEXT   0x10

#define DETECT_PCRE_RAWBYTES      0x20
#define DETECT_PCRE_URI           0x40

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

    u_int8_t flags;

    char *capname;
} DetectPcreData;

/* prototypes */
void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

