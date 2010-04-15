/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_REFERENCE_H__
#define __DETECT_REFERENCE_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

/** Signature reference list */
typedef struct References_ {
    char *reference;    /**< reference data */
    struct References_ *next; /**< next reference in the signature */
} References;

/**
 * \typedef DetectReferenceData
 * A typedef for DetectReferenceData_
 */

typedef struct DetectReferenceData_ {
    char *reference; /**< 0 reference prefix 1 - reference data */
} DetectReferenceData;


/**
 * Registration function for reference: keyword
 */

void DetectReferenceRegister (void);

/**
 * This function registers unit tests for Reference
 */

void ReferenceRegisterTests(void);

#endif /*__DETECT_REFERENCE_H__ */
