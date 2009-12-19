#ifndef __DETECT_WINDOW_H__
#define __DETECT_WINDOW_H__

#define MIN_WINDOW_VALUE 0
#define MAX_WINDOW_VALUE 65535

typedef struct DetectWindowData_ {
    uint8_t negated;	/** negated? 1=True : 0=False */
    uint16_t size;     /** window size to match */
} DetectWindowData;

/* prototypes */
void DetectWindowRegister (void);

#endif /* __DETECT_WINDOW_H__ */

