/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_IPOPTS_H__
#define __DETECT_IPOPTS_H__

#include "decode-events.h"
#include "decode-ipv4.h"

/**
 * \struct DetectIpOptsData_
 * DetectIpOptsData_ is used to store ipopts: input value
 */

/**
 * \typedef DetectIpOptsData
 * A typedef for DetectIpOptsData_
 */

typedef struct DetectIpOptsData_ {
    uint8_t ipopt;  /**< Ip option */
} DetectIpOptsData;

/**
 * Registration function for ipopts: keyword
 */

void DetectIpOptsRegister (void);

#ifdef DETECT_EVENTS

/**
 * Used to check ipopts:any
 */

#define IPV4_OPT_ANY    0xff

/**
 * \struct DetectIpOptss_
 * DetectIpOptss_ is used to store supported iptops values
 */

struct DetectIpOptss_ {
    char *ipopt_name;   /**< Ip option name */
    uint8_t code;   /**< Ip option value */
} DIpOpts[] = {
    { "rr", IPV4_OPT_RR, },
    { "lsrr", IPV4_OPT_LSRR, },
    { "eol", IPV4_OPT_EOL, },
    { "nop", IPV4_OPT_NOP, },
    { "ts", IPV4_OPT_TS, },
    { "sec", IPV4_OPT_SEC, },
    { "ssrr", IPV4_OPT_SSRR, },
    { "satid", IPV4_OPT_SID, },
    { "any", IPV4_OPT_ANY, },
    { NULL, 0 },
};
#endif /* DETECT_EVENTS */
#endif /*__DETECT_IPOPTS_H__ */

