/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#ifndef __APP_LAYER_HTP_H__
#define __APP_LAYER_HTP_H__

#include "util-radix-tree.h"

#include <htp/htp.h>

#define HTP_FLAG_STATE_OPEN         0x01    /**< Flag to indicate that HTTP
                                             connection is open */
#define HTP_FLAG_STATE_CLOSED       0x02    /**< Flag to indicate that HTTP
                                             connection is closed */
#define HTP_FLAG_STATE_DATA         0x04    /**< Flag to indicate that HTTP
                                             connection needs more data */
#define HTP_FLAG_STATE_ERROR        0x08    /**< Flag to indicate that an error
                                             has been occured on HTTP
                                             connection */
#define HTP_FLAG_NEW_BODY_SET       0x10    /**< Flag to indicate that HTTP
                                             has parsed a new body (for
                                             pcre) */
#define HTP_FLAG_NEW_REQUEST        0x20    /**< Flag to indicate that we have
                                                 a new HTTP requesta and we
                                                 need to log it */


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
typedef struct HtpBodyChunk_ {
    uint8_t *data;              /**< Pointer to the data of the chunk */
    uint32_t len;               /**< Length of the chunk */
    struct HtpBodyChunk_ *next; /**< Pointer to the next chunk */
    uint32_t id;                /**< number of chunk of the current body */
} HtpBodyChunk;

/** Struct used to hold all the chunks of a body on a request */
typedef struct HtpBody_ {
    HtpBodyChunk *first; /**< Pointer to the first chunk */
    HtpBodyChunk *last;  /**< Pointer to the last chunk */
    uint32_t nchunks;    /**< Number of chunks in the current operation */
    uint8_t operation;   /**< This flag indicate if it's a request
                              or a response */
    uint8_t pcre_flags;  /**< This flag indicate if no chunk matched
                              any pcre (so we can free() without waiting) */
} HtpBody;

typedef struct HtpState_ {

    htp_connp_t *connp;     /**< Connection parser structure for
                                 each connection */
    HtpBody body;           /**< Body of the request (if any) */
    size_t new_in_tx_index; /**< Index to indicate that after this we have
                                 new requests to log */
    uint8_t flags;
} HtpState;

void RegisterHTPParsers(void);
void HTPParserRegisterTests(void);
void HTPAtExitPrintStats(void);
void HTPFreeConfig(void);

htp_tx_t *HTPTransactionMain(const HtpState *);

int HTPCallbackRequestBodyData(htp_tx_data_t *);
void HtpBodyPrint(HtpBody *);
void HtpBodyFree(HtpBody *);
void AppLayerHtpRegisterExtraCallbacks(void);
/* To free the state from unittests using app-layer-htp */
void HTPStateFree(void *);
void AppLayerHtpEnableRequestBodyCallback(void);

#endif	/* __APP_LAYER_HTP_H__ */

