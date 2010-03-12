/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file detect-detection-filter.h
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 *
 */

#ifndef __DETECT_DETECTION_FILTER_H__
#define __DETECT_DETECTION_FILTER_H__

#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"

#define TRACK_DST      1
#define TRACK_SRC      2

/**
 * \typedef DetectDetectionFilterData
 * A typedef for DetectDetectionFilterData_
 *
 */
typedef struct DetectDetectionFilterData_ {
    uint8_t track;      /**< Track type: by_src, by_dst */
    uint32_t count;     /**< Event count */
    uint32_t seconds;   /**< Event seconds */
} DetectDetectionFilterData;

/**
 *\typedef DetectDetectionFilterEntry
 * A typedef for DetecDetectionFilterEntry_
 *
 */
typedef struct DetectDetectionFilterEntry_ {
    uint8_t track;      /**< Track type: by_src, by_dst */
    uint32_t seconds;   /**< Event seconds */

    Address addr;       /**< Var used to store dst or src addr */

    uint32_t tv_sec1;   /**< Var for time control */
    uint32_t current_count; /**< Var for count control */
} DetectDetectionFilterEntry;


/**
 * Registration function for detection_filter: keyword
 */

void DetectDetectionFilterRegister (void);

/**
 * This function registers unit tests for detection_filter
 */

void DetectDetectionFilterRegisterTests(void);

#endif /*__DETECT_DETECTION_FILTER_H__ */

