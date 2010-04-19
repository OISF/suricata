/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 */

#ifndef __DETECT_ICMP_ID_H__
#define __DETECT_ICMP_ID_H__

typedef struct DetectIcmpIdData_ {
    uint16_t id; /**< id in network byte error */
} DetectIcmpIdData;

/* prototypes */
void DetectIcmpIdRegister(void);

#endif /* __DETECT_ICMP_ID__ */
