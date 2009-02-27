#ifndef __DETECT_DSIZE_H__
#define __DETECT_DSIZE_H__

#define DETECTDSIZE_LT 0
#define DETECTDSIZE_EQ 1
#define DETECTDSIZE_GT 2
#define DETECTDSIZE_RA 3

typedef struct _DetectDsizeData {
    u_int16_t dsize;
    u_int16_t dsize2;
    u_int8_t mode;
} DetectDsizeData;

/* prototypes */
void DetectDsizeRegister (void);

#endif /* __DETECT_DSIZE_H__ */

