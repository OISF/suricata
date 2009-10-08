/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FLAGS_H__
#define __DETECT_FLAGS_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

/**
 * \struct DetectFlagsData_
 * DetectFlagsData_ is used to store flags: input value
 */

/**
 * \typedef DetectFlagsData
 * A typedef for DetectFlagsData_
 */

typedef struct DetectFlagsData_ {
    uint8_t flags;  /**< TCP flags */
    uint8_t modifier; /**< !(1) +(2) *(3) modifiers */
    uint8_t ignored_flags;  /**< Ignored TCP flags defined by modifer , */
} DetectFlagsData;

/**
 * Registration function for flags: keyword
 */

void DetectFlagsRegister (void);

/**
 * This function registers unit tests for Flags
 */

void FlagsRegisterTests(void);

#endif /*__DETECT_FLAGS_H__ */
