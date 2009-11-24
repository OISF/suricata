/*
 * \file:   app-layer-htp.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on November 14, 2009, 12:48 AM
 */

#ifndef _APP_LAYER_HTP_H
#define	_APP_LAYER_HTP_H

#include <htp/htp.h>

typedef struct HtpState_ {

    htp_connp_t *connp; /**< Connection parser structure for each connection */

} HtpState;

htp_cfg_t *cfg; /**< Config structure for HTP library */

void RegisterHTPParsers(void);
void HTPParserRegisterTests(void);
#endif	/* _APP_LAYER_HTP_H */

