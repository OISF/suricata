#ifndef __DETECT_ISDATAAT_H__
#define __DETECT_ISDATAAT_H__

#define ISDATAAT_RELATIVE 0x01
#define ISDATAAT_RAWBYTES 0x02

#define ISDATAAT_MIN 0
#define ISDATAAT_MAX 65535

typedef struct DetectIsdataatData_ {
    uint16_t dataat;     /* data offset to match */
    uint8_t flags; /* isdataat options*/
} DetectIsdataatData;

/* prototypes */
void DetectIsdataatRegister (void);

#endif /* __DETECT_ISDATAAT_H__ */

