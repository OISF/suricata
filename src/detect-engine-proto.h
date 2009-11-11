#ifndef __DETECT_PROTO_H__
#define __DETECT_PROTO_H__

#define DETECT_PROTO_ANY 0x1 /**< Flag to indicate that given protocol
                                  is considered as IP */

typedef struct DetectProto_ {
    uint8_t proto[256/8]; /**< bit array for 256 protocol bits */
    uint8_t flags;
} DetectProto;

/* prototypes */
void DetectProtoRegister (void);
int DetectProtoParse(DetectProto *dp, char *str);
int DetectProtoContainsProto(DetectProto *, int);

#endif /* __DETECT_PROTO_H__ */

