/*
 * \file:   app-layer-htp.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on November 14, 2009, 12:48 AM
 */

#ifndef _APP_LAYER_HTP_H
#define	_APP_LAYER_HTP_H

#include <htp/htp.h>

#define HTP_FLAG_STATE_OPEN     0x01    /**< Flag to indicate that HTTP connection
                                             is open */
#define HTP_FLAG_STATE_CLOSED   0x02    /**< Flag to indicate that HTTP connection
                                             is closed */

typedef struct HtpState_ {

    htp_connp_t *connp; /**< Connection parser structure for each connection */
    uint8_t flags;

} HtpState;

htp_cfg_t *cfg; /**< Config structure for HTP library */

void RegisterHTPParsers(void);
void HTPParserRegisterTests(void);
void HTPAtExitPrintStats(void);
void HTPFreeConfig(void);
#endif	/* _APP_LAYER_HTP_H */

