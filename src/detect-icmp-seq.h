/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_ICMP_SEQ_H__
#define __DETECT_ICMP_SEQ_H__

typedef struct DetectIcmpSeqData_ {
    uint16_t seq;
} DetectIcmpSeqData;

/* prototypes */
void DetectIcmpSeqRegister(void);

#endif /* __DETECT_ICMP_SEQ__ */
