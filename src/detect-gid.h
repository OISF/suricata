/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_GID_H__
#define __DETECT_GID_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

/**
 * \struct DetectGidData_
 * DetectGidData_ is used to store gid: input value
 */

/**
 * \typedef DetectGidData
 * A typedef for DetectGidData_
 */

typedef struct DetectGidData_ {
    uint32_t gid;  /**< Rule gid */
} DetectGidData;

/**
 * Registration function for gid: keyword
 */

void DetectGidRegister (void);

/**
 * This function registers unit tests for Gid
 */

void GidRegisterTests(void);

#endif /*__DETECT_GID_H__ */
