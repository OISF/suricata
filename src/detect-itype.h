/**
 * Copyright (c) 2009 Open Information Security Foundation
 */

#ifndef __DETECT_ITYPE_H__
#define __DETECT_ITYPE_H__

#define DETECT_ITYPE_EQ   0   /**< "equal" operator */
#define DETECT_ITYPE_LT   1   /**< "less than" operator */
#define DETECT_ITYPE_GT   2   /**< "greater than" operator */
#define DETECT_ITYPE_RN   3   /**< "range" operator */

typedef struct DetectITypeData_ {
    uint8_t type1;
    uint8_t type2;

    uint8_t mode;
} DetectITypeData;

/* prototypes */
void DetectITypeRegister(void);

#endif /* __DETECT_ITYPE_H__ */
