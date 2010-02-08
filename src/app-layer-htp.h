/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file:   app-layer-htp.h
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Created on November 14, 2009, 12:48 AM
 */

#ifndef __APP_LAYER_HTP_H__
#define __APP_LAYER_HTP_H__

#include <htp/htp.h>

#define HTP_FLAG_STATE_OPEN     0x01    /**< Flag to indicate that HTTP
                                             connection is open */
#define HTP_FLAG_STATE_CLOSED   0x02    /**< Flag to indicate that HTTP
                                             connection is closed */
#define HTP_FLAG_STATE_DATA     0x04    /**< Flag to indicate that HTTP
                                             connection needs more data */
#define HTP_FLAG_STATE_ERROR    0x08    /**< Flag to indicate that an error
                                             has been occured on HTTP
                                             connection */

#define HTP_NEW_BODY_SET        0x10    /**< Flag to indicate that HTTP
                                             has parsed a new body (for
                                             pcre) */


enum {
    HTP_BODY_NONE,                      /**< Flag to indicate the current
                                             operation */
    HTP_BODY_REQUEST,                   /**< Flag to indicate that the
                                             current operation is a request */
    HTP_BODY_RESPONSE                   /**< Flag to indicate that the current
                                          * operation is a response */
};

#define HTP_PCRE_NONE           0x00    /**< No pcre executed yet */
#define HTP_PCRE_DONE           0x01    /**< Flag to indicate that pcre has
                                             done some inspection in the
                                             chunks */
#define HTP_PCRE_HAS_MATCH      0x02    /**< Flag to indicate that the chunks
                                             matched on some rule */

/** Struct used to hold chunks of a body on a request */
typedef struct BodyChunk_ {
    uint8_t *data;              /**< Pointer to the data of the chunk */
    uint32_t len;               /**< Length of the chunk */
    struct BodyChunk_ *next;    /**< Pointer to the next chunk */
    uint32_t id;                /**< number of chunk of the current body */
} BodyChunk;

/** Struct used to hold all the chunks of a body on a request */
typedef struct Body_ {
    BodyChunk *first;    /**< Pointer to the first chunk */
    BodyChunk *last;     /**< Pointer to the last chunk */
    uint32_t nchunks;    /**< Number of chunks in the current operation */
    uint8_t operation;   /**< This flag indicate if it's a request
                              or a response */
    uint8_t pcre_flags;  /**< This flag indicate if no chunk matched
                              any pcre (so we can free() without waiting) */
} HtpBody;

typedef struct HtpState_ {

    htp_connp_t *connp;       /**< Connection parser structure for
                                   each connection */
    uint8_t flags;
    list_t *recent_in_tx;     /**< Point to the new received HTTP request */
    HtpBody body;             /**< Body of the request (if any) */

} HtpState;

htp_cfg_t *cfg; /**< Config structure for HTP library */

void RegisterHTPParsers(void);
void HTPParserRegisterTests(void);
void HTPAtExitPrintStats(void);
void HTPFreeConfig(void);

htp_tx_t *HTPTransactionMain(const HtpState *);

int HTPCallbackRequestBodyData(htp_tx_data_t *);
void HtpBodyPrint(HtpBody *);
void HtpBodyFree(HtpBody *);
void AppLayerHtpRegisterExtraCallbacks(void);

#endif	/* __APP_LAYER_HTP_H__ */

