#ifndef __DETECT_DSIZE_H__
#define __DETECT_DSIZE_H__

#define DETECTDSIZE_LT 0
#define DETECTDSIZE_EQ 1
#define DETECTDSIZE_GT 2
#define DETECTDSIZE_RA 3

typedef struct DetectDsizeData_ {
    uint16_t dsize;
    uint16_t dsize2;
    uint8_t mode;
} DetectDsizeData;

/* prototypes */
void DetectDsizeRegister (void);

#endif /* __DETECT_DSIZE_H__ */

