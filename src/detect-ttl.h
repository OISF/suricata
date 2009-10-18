/*
 * File:   detect-stream_size.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_TTL_H
#define	_DETECT_TTL_H

#define DETECT_TTL_LT   0
#define DETECT_TTL_EQ   1
#define DETECT_TTL_GT   2
#define DETECT_TTL_RA   3

typedef struct DetectTtlData_ {
    uint8_t ttl1;
    uint8_t ttl2;
    uint8_t mode;
}DetectTtlData;

void DetectTtlRegister(void);

#endif	/* _DETECT_TTL_H */

