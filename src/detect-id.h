#ifndef __DETECT_ID_H__
#define __DETECT_ID_H__


#define DETECT_IPID_MIN 0
#define DETECT_IPID_MAX 65536

typedef struct DetectIdData_ {
    uint16_t id;     /** ip->id to match */
} DetectIdData;

/* prototypes */
void DetectIdRegister (void);

#endif /* __DETECT_ID_H__ */

