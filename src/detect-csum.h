#ifndef __DETECT_CSUM_H__
#define __DETECT_CSUM_H__

#define DETECT_CSUM_VALID "valid"
#define DETECT_CSUM_INVALID "invalid"

typedef struct DetectCsumData_ {
    /* Indicates if the csum-<protocol> keyword in a rule holds the
       keyvalue "valid" or "invalid" */
    int16_t valid;
} DetectCsumData;

void DetectCsumRegister(void);

#endif /* __DETECT_CSUM_H__ */

