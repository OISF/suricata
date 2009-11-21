/*
 * \file:   app-layer-htp.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on November 14, 2009, 12:48 AM
 */

#ifndef _APP_LAYER_HTP_H
#define	_APP_LAYER_HTP_H

#include <htp/htp.h>

typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    /** \todo more.. */
} HtpRequestMethod;

typedef uint16_t HtpResponseCode;

typedef struct HtpState_ {
    HtpRequestMethod method;

    HtpResponseCode response_code;

    htp_connp_t *connp; /**< Connection parser structure for each connection */

} HtpState;

htp_cfg_t *cfg; /**< Config structure for HTP library */

void RegisterHTPParsers(void);
void HTPParserRegisterTests(void);
#endif	/* _APP_LAYER_HTP_H */

