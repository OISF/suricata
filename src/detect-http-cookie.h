/**Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_HTTP_COOKIE_H
#define	_DETECT_HTTP_COOKIE_H

typedef struct DetectHttpCookieData_ {
    uint8_t *data;
    uint8_t data_len;
} DetectHttpCookieData;

/* prototypes */
void DetectHttpCookieRegister (void);

#endif	/* _DETECT_HTTP_COOKIE_H */

