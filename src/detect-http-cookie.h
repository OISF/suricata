/**Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_HTTP_COOKIE_H
#define	_DETECT_HTTP_COOKIE_H

#define DETECT_AL_HTTP_COOKIE_NOCASE   0x01
#define DETECT_AL_HTTP_COOKIE_NEGATED  0x02

typedef struct DetectHttpCookieData_ {
    uint8_t *data;
    uint8_t data_len;
    uint8_t flags;
} DetectHttpCookieData;

/* prototypes */
void DetectHttpCookieRegister (void);

int DetectHttpCookieDoMatch(DetectEngineThreadCtx *det_ctx, Signature *s,
        SigMatch *sm, Flow *f, uint8_t flags, void *state);

#endif	/* _DETECT_HTTP_COOKIE_H */

