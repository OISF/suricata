#ifndef __DETECT_PKTVAR_H__
#define __DETECT_PKTVAR_H__

#define DETECT_CONTENT_NOCASE        0x01

typedef struct DetectPktvarData_ {
    char *name;
    u_int8_t *content;
    u_int8_t content_len;
    u_int8_t flags;
} DetectPktvarData;

/* prototypes */
void DetectPktvarRegister (void);

#endif /* __DETECT_PKTVAR_H__ */

