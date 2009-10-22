/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FRAGBITS_H__
#define __DETECT_FRAGBITS_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

/**
 * \struct DetectFragBitsData_
 * DetectFragBitsData_ is used to store fragbits: input value
 */

/**
 * \typedef DetectFragBitsData
 * A typedef for DetectFragBitsData_
 */

typedef struct DetectFragBitsData_ {
    uint16_t fragbits;  /**< TCP fragbits */
    uint8_t modifier; /**< !(1) +(2) *(3) modifiers */
} DetectFragBitsData;

/**
 * Registration function for fragbits: keyword
 */

void DetectFragBitsRegister (void);

/**
 * This function registers unit tests for FragBits
 */

void FragBitsRegisterTests(void);

#endif /*__DETECT_FRAGBITS_H__ */
