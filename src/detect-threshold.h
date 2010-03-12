/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_THRESHOLD_H__
#define __DETECT_THRESHOLD_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

#define TYPE_LIMIT     1
#define TYPE_BOTH      2
#define TYPE_THRESHOLD 3
#define TYPE_DETECTION 4

#define TRACK_DST      1
#define TRACK_SRC      2

/**
 * \typedef DetectThresholdData
 * A typedef for DetectThresholdData_
 */

typedef struct DetectThresholdData_ {
    uint8_t type;       /**< Threshold type : limit , threshold, both, detection_filter */
    uint8_t track;      /**< Track type: by_src, by_src */
    uint32_t count;     /**< Event count */
    uint32_t seconds;   /**< Event seconds */
    uint32_t sid;       /**< Signature id */
    uint8_t gid;        /**< Signature group id */
    uint8_t ipv;        /**< Packet ip version */
} DetectThresholdData;

typedef struct DetectThresholdEntry_ {
    uint8_t type;       /**< Threshold type : limit , threshold, both */
    uint8_t track;      /**< Track type: by_src, by_src */
    uint32_t seconds;   /**< Event seconds */
    uint32_t sid;       /**< Signature id */
    uint8_t gid;        /**< Signature group id */
    uint8_t ipv;        /**< Packet ip version */

    Address addr;       /**< Var used to store dst or src addr */

    uint32_t tv_sec1;   /**< Var for time control */
    uint32_t current_count; /**< Var for count control */
} DetectThresholdEntry;


/**
 * Registration function for threshold: keyword
 */

void DetectThresholdRegister (void);

/**
 * This function registers unit tests for Threshold
 */

void ThresholdRegisterTests(void);

#endif /*__DETECT_THRESHOLD_H__ */
