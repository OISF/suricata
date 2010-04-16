/* Copyright (c) 2009, 2010 Open Information Security Foundation */

/**
 *  \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_REFERENCE_H__
#define __DETECT_REFERENCE_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

/** Signature reference list */
typedef struct Reference_ {
    char *key;                  /**< pointer to key */
    char *reference;            /**< reference data */
    struct Reference_ *next;   /**< next reference in the signature */
} Reference;

/**
 * Registration function for reference: keyword
 */
void DetectReferenceRegister (void);

/**
 * This function registers unit tests for Reference
 */
void ReferenceRegisterTests(void);

/**
 * Free function for a Reference object
 */
void DetectReferenceFree(Reference *);

#endif /*__DETECT_REFERENCE_H__ */

