/*
 * File:   detect-stream_size.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_TTL_H
#define	_DETECT_TTL_H

#define DETECT_TTL_LT   0   /**< "less than" operator */
#define DETECT_TTL_EQ   1   /**< "equals" operator (default) */
#define DETECT_TTL_GT   2   /**< "greater than" operator */
#define DETECT_TTL_RA   3   /**< "range" operator */

typedef struct DetectTtlData_ {
    uint8_t ttl1;   /**< first ttl value in the signature*/
    uint8_t ttl2;   /**< second ttl value in the signature, in case of range
                         operator*/
    uint8_t mode;   /**< operator used in the signature */
}DetectTtlData;

void DetectTtlRegister(void);

#endif	/* _DETECT_TTL_H */

