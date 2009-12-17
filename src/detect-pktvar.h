#ifndef __DETECT_PKTVAR_H__
#define __DETECT_PKTVAR_H__

typedef struct DetectPktvarData_ {
    char *name;
    uint8_t *content;
    uint8_t content_len;
    uint8_t flags;
} DetectPktvarData;

/* prototypes */
void DetectPktvarRegister (void);

#endif /* __DETECT_PKTVAR_H__ */

