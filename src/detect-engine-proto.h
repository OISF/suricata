#ifndef __DETECT_PROTO_H__
#define __DETECT_PROTO_H__

#define DETECT_PROTO_ANY 0x1

typedef struct DetectProto_ {
    u_int8_t proto[32]; /* bitarray 256/8 */
    u_int8_t flags;
} DetectProto;

/* prototypes */
void DetectProtoRegister (void);
int DetectProtoParse(DetectProto *dp, char *str);

#endif /* __DETECT_PROTO_H__ */

