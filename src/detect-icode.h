/**
 * Copyright (c) 2009 Open Information Security Foundation
 */

#ifndef __DETECT_ICODE_H__
#define __DETECT_ICODE_H__

#define DETECT_ICODE_EQ   0   /**< "equal" operator */
#define DETECT_ICODE_LT   1   /**< "less than" operator */
#define DETECT_ICODE_GT   2   /**< "greater than" operator */
#define DETECT_ICODE_RN   3   /**< "range" operator */

typedef struct DetectICodeData_ {
    uint8_t code1;
    uint8_t code2;

    uint8_t mode;
}DetectICodeData;

/* prototypes */
void DetectICodeRegister(void);

#endif /* __DETECT_ICODE_H__ */
