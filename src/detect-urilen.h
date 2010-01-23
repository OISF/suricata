/*
 * File:   detect-urilen.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_URILEN_H
#define	_DETECT_URILEN_H

#define DETECT_URILEN_LT   0   /**< "less than" operator */
#define DETECT_URILEN_GT   1   /**< "greater than" operator */
#define DETECT_URILEN_RA   2   /**< range operator */
#define DETECT_URILEN_EQ   3   /**< equal operator */

typedef struct DetectUrilenData_ {
    uint16_t urilen1;   /**< 1st Uri Length value in the signature*/
    uint16_t urilen2;   /**< 2nd Uri Length value in the signature*/
    uint8_t mode;   /**< operator used in the signature */
}DetectUrilenData;

void DetectUrilenRegister(void);

#endif	/* _DETECT_URILEN_H */

