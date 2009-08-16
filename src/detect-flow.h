#ifndef __DETECT_FLOW_H__
#define __DETECT_FLOW_H__

typedef struct DetectFlowData_ {
    uint8_t flags;     /* flags to match */
    uint8_t match_cnt; /* number of matches we need */
} DetectFlowData;

/* prototypes */
void DetectFlowRegister (void);

#endif /* __DETECT_FLOW_H__ */

