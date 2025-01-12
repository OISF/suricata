/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \defgroup httplayer HTTP layer support
 *
 * @{
 */

/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#ifndef SURICATA_APP_LAYER_HTP_H
#define SURICATA_APP_LAYER_HTP_H

#include "rust.h"
#include "app-layer-frames.h"

#include "htp/htp_rs.h"

/* default request body limit */
#define HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT           4096U
#define HTP_CONFIG_DEFAULT_RESPONSE_BODY_LIMIT          4096U
#define HTP_CONFIG_DEFAULT_REQUEST_INSPECT_MIN_SIZE     32768U
#define HTP_CONFIG_DEFAULT_REQUEST_INSPECT_WINDOW       4096U
#define HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_MIN_SIZE    32768U
#define HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_WINDOW      4096U
#define HTP_CONFIG_DEFAULT_FIELD_LIMIT                  18000U

#define HTP_CONFIG_DEFAULT_LZMA_LAYERS 0U
/* default libhtp lzma limit, taken from libhtp. */
#define HTP_CONFIG_DEFAULT_LZMA_MEMLIMIT                1048576U
#define HTP_CONFIG_DEFAULT_COMPRESSION_BOMB_LIMIT       1048576U
// 100000 usec is 0.1 sec
#define HTP_CONFIG_DEFAULT_COMPRESSION_TIME_LIMIT 100000

#define HTP_CONFIG_DEFAULT_RANDOMIZE                    1
#define HTP_CONFIG_DEFAULT_RANDOMIZE_RANGE              10

// 0x0001 not used
#define HTP_FLAG_STATE_CLOSED_TS    0x0002    /**< Flag to indicate that HTTP
                                             connection is closed */
#define HTP_FLAG_STATE_CLOSED_TC                                                                   \
    0x0004 /**< Flag to indicate that HTTP                                                         \
          connection is closed */

enum {
    HTP_BODY_REQUEST_NONE = 0,
    HTP_BODY_REQUEST_MULTIPART, /* POST, MP */
    HTP_BODY_REQUEST_POST,      /* POST, no MP */
    HTP_BODY_REQUEST_PUT,
};

enum {
    /* suricata errors/warnings */
    HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR = 200,
    HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA = 201,
    HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER = 202,

    HTTP_DECODER_EVENT_TOO_MANY_WARNINGS = 203,
    HTTP_DECODER_EVENT_RANGE_INVALID = 204,
    HTTP_DECODER_EVENT_FILE_NAME_TOO_LONG = 205,
    HTTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE = 206,
};

typedef enum HtpSwfCompressType_ {
    HTTP_SWF_COMPRESSION_NONE = 0,
    HTTP_SWF_COMPRESSION_ZLIB,
    HTTP_SWF_COMPRESSION_LZMA,
    HTTP_SWF_COMPRESSION_BOTH,
} HtpSwfCompressType;

typedef struct HTPCfgDir_ {
    uint32_t body_limit;
    uint32_t inspect_min_size;
    uint32_t inspect_window;
} HTPCfgDir;

/** Need a linked list in order to keep track of these */
typedef struct HTPCfgRec_ {
    htp_cfg_t           *cfg;
    struct HTPCfgRec_   *next;

    /** max size of the client body we inspect */
    int                 randomize;
    int                 randomize_range;
    int                 http_body_inline;

    int                 swf_decompression_enabled;
    HtpSwfCompressType  swf_compression_type;
    uint32_t            swf_decompress_depth;
    uint32_t            swf_compress_depth;

    HTPCfgDir request;
    HTPCfgDir response;

    bool uri_include_all; /**< use all info in uri (bool) */
} HTPCfgRec;

/** Struct used to hold chunks of a body on a request */
struct HtpBodyChunk_ {
    struct HtpBodyChunk_ *next; /**< Pointer to the next chunk */
    int logged;
    StreamingBufferSegment sbseg;
} __attribute__((__packed__));
typedef struct HtpBodyChunk_ HtpBodyChunk;

/** Struct used to hold all the chunks of a body on a request */
typedef struct HtpBody_ {
    HtpBodyChunk *first; /**< Pointer to the first chunk */
    HtpBodyChunk *last;  /**< Pointer to the last chunk */

    StreamingBuffer *sb;

    /* Holds the length of the htp request body seen so far */
    uint64_t content_len_so_far;
    /* parser tracker */
    uint64_t body_parsed;
    /* inspection tracker */
    uint64_t body_inspected;
} HtpBody;

#define HTP_BOUNDARY_SET        BIT_U8(1)    /**< We have a boundary string */
#define HTP_FILENAME_SET        BIT_U8(3)    /**< filename is registered in the flow */
#define HTP_DONTSTORE           BIT_U8(4)    /**< not storing this file */
#define HTP_STREAM_DEPTH_SET    BIT_U8(5)    /**< stream-depth is set */

/** Now the Body Chunks will be stored per transaction, at
  * the tx user data */
typedef struct HtpTxUserData_ {
    /* Body of the request (if any) */
    uint8_t request_body_init;
    uint8_t response_body_init;

    uint8_t request_has_trailers;
    uint8_t response_has_trailers;

    uint8_t tsflags;
    uint8_t tcflags;

    uint8_t request_body_type;

    HtpBody request_body;
    HtpBody response_body;

    uint8_t *request_headers_raw;
    uint8_t *response_headers_raw;
    uint32_t request_headers_raw_len;
    uint32_t response_headers_raw_len;

    MimeStateHTTP *mime_state;

    HttpRangeContainerBlock *file_range; /**< used to assign track ids to range file */

    AppLayerTxData tx_data;
    FileContainer files_ts;
    FileContainer files_tc;
} HtpTxUserData;

typedef struct HtpState_ {
    /* Connection parser structure for each connection */
    htp_connp_t *connp;
    /* Connection structure for each connection */
    htp_conn_t *conn;
    Flow *f;                /**< Needed to retrieve the original flow when using HTPLib callbacks */
    uint64_t transaction_cnt;
    const struct HTPCfgRec_ *cfg;
    uint16_t flags;
    uint16_t events;
    uint16_t htp_messages_count; /**< Number of already logged messages */
    uint32_t file_track_id;      /**< used to assign file track ids to files */
    uint64_t last_request_data_stamp;
    uint64_t last_response_data_stamp;
    StreamSlice *slice;
    FrameId request_frame_id;
    FrameId response_frame_id;
    AppLayerStateData state_data;
} HtpState;

/** part of the engine needs the request body (e.g. http_client_body keyword) */
#define HTP_REQUIRE_REQUEST_BODY (1 << 0)
/** part of the engine needs the request file (e.g. log-file module) */
#define HTP_REQUIRE_REQUEST_FILE        (1 << 2)
/** part of the engine needs the request body (e.g. file_data keyword) */
#define HTP_REQUIRE_RESPONSE_BODY       (1 << 3)

SC_ATOMIC_EXTERN(uint32_t, htp_config_flags);

void RegisterHTPParsers(void);
void HTPAtExitPrintStats(void);
void HTPFreeConfig(void);

/* To free the state from unittests using app-layer-htp */
void HTPStateFree(void *);
void AppLayerHtpEnableRequestBodyCallback(void);
void AppLayerHtpEnableResponseBodyCallback(void);
void AppLayerHtpNeedFileInspection(void);
void AppLayerHtpPrintStats(void);

void HTPConfigure(void);

void HtpConfigCreateBackup(void);
void HtpConfigRestoreBackup(void);

void *HtpGetTxForH2(void *);

#endif /* SURICATA_APP_LAYER_HTP_H */

/**
 * @}
 */
