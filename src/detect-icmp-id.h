/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file detect-icmp-id.h
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 */

#ifndef __DETECT_ICMP_ID_H__
#define __DETECT_ICMP_ID_H__

typedef struct DetectIcmpIdData_ {
    uint16_t id;
} DetectIcmpIdData;

/* prototypes */
void DetectIcmpIdRegister(void);

#endif /* __DETECT_ICMP_ID__ */
