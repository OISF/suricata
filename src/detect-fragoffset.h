/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FRAGOFFSET_H__
#define __DETECT_FRAGOFFSET_H__

#define FRAG_LESS 1
#define FRAG_MORE 2

typedef struct DetectFragOffsetData_ {
    uint16_t frag_off;
    uint8_t mode;
} DetectFragOffsetData;

/* prototypes */
void DetectFragOffsetRegister(void);

#endif /* __DETECT_FRAGOFFSET__ */
