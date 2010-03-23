#ifndef __DETECT_PCRE_H__
#define __DETECT_PCRE_H__

#define DETECT_PCRE_RELATIVE      0x01
#define DETECT_PCRE_RAWBYTES      0x02
#define DETECT_PCRE_URI           0x04

#define DETECT_PCRE_CAPTURE_PKT   0x08
#define DETECT_PCRE_CAPTURE_FLOW  0x10
#define DETECT_PCRE_MATCH_LIMIT   0x20

#define DETECT_PCRE_HTTP_BODY_AL  0x40

typedef struct DetectPcreData_ {
    /* pcre options */
    pcre *re;
    pcre_extra *sd;
    int opts;

    uint8_t flags;
    uint8_t negate;

    char *capname;
    uint16_t capidx;
} DetectPcreData;

/* prototypes */
int DetectPcrePayloadMatch(DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
void DetectPcreRegister (void);

#endif /* __DETECT_PCRE_H__ */

