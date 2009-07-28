#ifndef __DETECT_FLOWVAR_H__
#define __DETECT_FLOWVAR_H__

#define DETECT_CONTENT_NOCASE        0x01

typedef struct DetectFlowvarData_ {
    char *name;
    u_int16_t idx;
    u_int8_t *content;
    u_int8_t content_len;
    u_int8_t flags;
} DetectFlowvarData;

/* prototypes */
void DetectFlowvarRegister (void);

#endif /* __DETECT_FLOWVAR_H__ */

