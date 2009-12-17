#ifndef __DETECT_FLOWVAR_H__
#define __DETECT_FLOWVAR_H__

typedef struct DetectFlowvarData_ {
    char *name;
    uint16_t idx;
    uint8_t *content;
    uint8_t content_len;
    uint8_t flags;
} DetectFlowvarData;

/* prototypes */
void DetectFlowvarRegister (void);

#endif /* __DETECT_FLOWVAR_H__ */

