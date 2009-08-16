#ifndef __DETECT_PROTO_H__
#define __DETECT_PROTO_H__

#define DETECT_PROTO_ANY 0x1

typedef struct DetectProto_ {
    uint8_t proto[256/8]; /* bitarray for 256 bits */
    uint8_t flags;
} DetectProto;

/* prototypes */
void DetectProtoRegister (void);
int DetectProtoParse(DetectProto *dp, char *str);

#endif /* __DETECT_PROTO_H__ */

