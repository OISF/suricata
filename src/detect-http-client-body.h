/**
 * Copyright (c) 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __DETECT_HTTP_CLIENT_BODY_H__
#define __DETECT_HTTP_CLIENT_BODY_H__

#define DETECT_AL_HTTP_CLIENT_BODY_NOCASE   0x01
#define DETECT_AL_HTTP_CLIENT_BODY_NEGATED  0x02

#include "util-spm-bm.h"

typedef struct DetectHttpClientBodyData_ {
    uint8_t *content;
    uint8_t content_len;
    uint8_t flags;
    BmCtx *bm_ctx;
} DetectHttpClientBodyData;

void DetectHttpClientBodyRegister(void);

#endif /* __DETECT_HTTP_CLIENT_BODY_H__ */
