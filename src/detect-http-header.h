/**
 * Copyright (c) 2010 Open Information Security Foundation.
 *
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

#ifndef __DETECT_HTTP_HEADER_H__
#define __DETECT_HTTP_HEADER_H__

#define DETECT_AL_HTTP_HEADER_NOCASE   0x01
#define DETECT_AL_HTTP_HEADER_NEGATED  0x02

typedef struct DetectHttpHeaderData_ {
    uint8_t *content;
    uint8_t content_len;
    uint8_t flags;
} DetectHttpHeaderData;

void DetectHttpHeaderRegister(void);

#endif /* __DETECT_HTTP_HEADER_H__ */
