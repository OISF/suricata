/* Copyright (C) 2012 BAE Systems
 * Copyright (C) 2021 Open Information Security Foundation
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#ifndef MIME_DECODE_H_
#define MIME_DECODE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "suricata.h"
#include "util-base64.h"
#include "util-debug.h"

/* Content Flags */
#define CTNT_IS_MSG           1
#define CTNT_IS_ENV           2
#define CTNT_IS_ENCAP         4
#define CTNT_IS_BODYPART      8
#define CTNT_IS_MULTIPART    16
#define CTNT_IS_ATTACHMENT   32
#define CTNT_IS_BASE64       64
#define CTNT_IS_QP          128
#define CTNT_IS_TEXT        256
#define CTNT_IS_HTML        512

/* URL Flags */
#define URL_IS_IP4          1
#define URL_IS_IP6          2
#define URL_IS_EXE          4

/* Anomaly Flags */
#define ANOM_INVALID_BASE64      1  /* invalid base64 chars */
#define ANOM_INVALID_QP          2  /* invalid quoted-printable chars */
#define ANOM_LONG_HEADER_NAME    4  /* header is abnormally long */
#define ANOM_LONG_HEADER_VALUE   8  /* header value is abnormally long
                                     * (includes multi-line) */
#define ANOM_LONG_LINE          16  /* Lines that exceed 998 octets */
#define ANOM_LONG_ENC_LINE      32  /* Lines that exceed 76 octets */
#define ANOM_MALFORMED_MSG      64  /* Misc msg format errors found */
#define ANOM_LONG_BOUNDARY     128  /* Boundary too long */
#define ANOM_LONG_FILENAME     256  /* filename truncated */

/* Publicly exposed size constants */
#define DATA_CHUNK_SIZE  3072  /* Should be divisible by 3 */
#define LINEREM_SIZE      256

/* Mime Parser Constants */
#define HEADER_READY    0x01
#define HEADER_STARTED  0x02
#define HEADER_DONE     0x03
#define BODY_STARTED    0x04
#define BODY_DONE       0x05
#define BODY_END_BOUND  0x06
#define PARSE_DONE      0x07
#define PARSE_ERROR     0x08

/**
 * \brief Mime Decoder Error Codes
 */
typedef enum MimeDecRetCode {
    MIME_DEC_OK = 0,
    MIME_DEC_MORE = 1,
    MIME_DEC_ERR_DATA = -1,
    MIME_DEC_ERR_MEM = -2,
    MIME_DEC_ERR_PARSE = -3,
    MIME_DEC_ERR_STATE = -4,    /**< parser in error state */
} MimeDecRetCode;

/**
 * \brief Structure for containing configuration options
 *
 */
typedef struct MimeDecConfig {
    bool decode_base64;             /**< Decode base64 bodies */
    bool decode_quoted_printable;   /**< Decode quoted-printable bodies */
    bool extract_urls;              /**< Extract and store URLs in data structure */
    ConfNode *extract_urls_schemes; /**< List of schemes of which to
                                         extract urls  */
    bool log_url_scheme;            /**< Log the scheme of extracted URLs */
    bool body_md5;                  /**< Compute md5 sum of body */
    uint32_t header_value_depth;  /**< Depth of which to store header values
                                       (Default is 2000) */
} MimeDecConfig;

/**
 * \brief This represents a header field name and associated value
 */
typedef struct MimeDecField {
    uint8_t *name;  /**< Name of the header field */
    uint32_t name_len;  /**< Length of the name */
    uint32_t value_len;  /**< Length of the value */
    uint8_t *value;  /**< Value of the header field */
    struct MimeDecField *next;  /**< Pointer to next field */
} MimeDecField;

/**
 * \brief This represents a URL value node in a linked list
 *
 * Since HTML can sometimes contain a high number of URLs, this
 * structure only features the URL host name/IP or those that are
 * pointing to an executable file (see url_flags to determine which).
 */
typedef struct MimeDecUrl {
    uint8_t *url;  /**< String representation of full or partial URL (lowercase) */
    uint32_t url_len;  /**< Length of the URL string */
    uint32_t url_flags;  /**< Flags indicating type of URL */
    struct MimeDecUrl *next;  /**< Pointer to next URL */
} MimeDecUrl;

/**
 * \brief This represents the MIME Entity (or also top level message) in a
 * child-sibling tree
 */
typedef struct MimeDecEntity {
    MimeDecField *field_list;  /**< Pointer to list of header fields */
    MimeDecUrl *url_list;  /**< Pointer to list of URLs */
    uint32_t body_len;  /**< Length of body (prior to any decoding) */
    uint32_t decoded_body_len;  /**< Length of body after decoding */
    uint32_t header_flags; /**< Flags indicating header characteristics */
    uint32_t ctnt_flags;  /**< Flags indicating type of content */
    uint32_t anomaly_flags;  /**< Flags indicating an anomaly in the message */
    uint32_t filename_len;  /**< Length of file attachment name */
    uint8_t *filename;  /**< Name of file attachment */
    uint8_t *ctnt_type;  /**< Quick access pointer to short-hand content type field */
    uint32_t ctnt_type_len;  /**< Length of content type field value */
    uint32_t msg_id_len;  /**< Quick access pointer to message Id */
    uint8_t *msg_id;  /**< Quick access pointer to message Id */
    struct MimeDecEntity *next;  /**< Pointer to list of sibling entities */
    struct MimeDecEntity *child;  /**< Pointer to list of child entities */
} MimeDecEntity;

/**
 * \brief Structure contains boundary and entity for the current node (entity)
 * in the stack
 *
 */
typedef struct MimeDecStackNode {
    MimeDecEntity *data;  /**< Pointer to the entity data structure */
    uint8_t *bdef;  /**< Copy of boundary definition for child entity */
    uint32_t bdef_len;  /**< Boundary length for child entity */
    bool is_encap;      /**< Flag indicating entity is encapsulated in message */
    struct MimeDecStackNode *next;  /**< Pointer to next item on the stack */
} MimeDecStackNode;

/**
 * \brief Structure holds the top of the stack along with some free reusable nodes
 *
 */
typedef struct MimeDecStack {
    MimeDecStackNode *top;  /**< Pointer to the top of the stack */
    MimeDecStackNode *free_nodes;  /**< Pointer to the list of free nodes */
    uint32_t free_nodes_cnt;  /**< Count of free nodes in the list */
} MimeDecStack;

/**
 * \brief Structure contains a list of value and lengths for robust data processing
 *
 */
typedef struct DataValue {
    uint8_t *value;  /**< Copy of data value */
    uint32_t value_len;  /**< Length of data value */
    struct DataValue *next;  /**< Pointer to next value in the list */
} DataValue;

/**
 * \brief Structure contains the current state of the MIME parser
 *
 */
typedef struct MimeDecParseState {
    MimeDecEntity *msg;  /**< Pointer to the top-level message entity */
    MimeDecStack *stack;  /**< Pointer to the top of the entity stack */
    uint8_t *hname;  /**< Copy of the last known header name */
    uint32_t hlen;  /**< Length of the last known header name */
    uint32_t hvlen; /**< Total length of value list */
    DataValue *hvalue;  /**< Pointer to the incomplete header value list */
    uint8_t linerem[LINEREM_SIZE];  /**< Remainder from previous line (for URL extraction) */
    uint16_t linerem_len;  /**< Length of remainder from previous line */
    uint8_t bvremain[B64_BLOCK];  /**< Remainder from base64-decoded line */
    uint8_t bvr_len;  /**< Length of remainder from base64-decoded line */
    uint8_t data_chunk[DATA_CHUNK_SIZE];  /**< Buffer holding data chunk */
    SCMd5 *md5_ctx;
    uint8_t md5[SC_MD5_LEN];
    bool has_md5;
    uint8_t state_flag;  /**<  Flag representing current state of parser */
    uint32_t data_chunk_len;  /**< Length of data chunk */
    int found_child;  /**< Flag indicating a child entity was found */
    int body_begin;  /**< Currently at beginning of body */
    int body_end;  /**< Currently at end of body */
    uint8_t current_line_delimiter_len; /**< Length of line delimiter */
    void *data;  /**< Pointer to data specific to the caller */
    int (*DataChunkProcessorFunc) (const uint8_t *chunk, uint32_t len,
            struct MimeDecParseState *state);  /**< Data chunk processing function callback */
} MimeDecParseState;

/* Config functions */
void MimeDecSetConfig(MimeDecConfig *config);
MimeDecConfig * MimeDecGetConfig(void);

/* Memory functions */
void MimeDecFreeEntity(MimeDecEntity *entity);
void MimeDecFreeField(MimeDecField *field);
void MimeDecFreeUrl(MimeDecUrl *url);

/* List functions */
MimeDecField * MimeDecAddField(MimeDecEntity *entity);
MimeDecField * MimeDecFindField(const MimeDecEntity *entity, const char *name);
int MimeDecFindFieldsForEach(const MimeDecEntity *entity, const char *name, int (*DataCallback)(const uint8_t *val, const size_t, void *data), void *data);
MimeDecEntity * MimeDecAddEntity(MimeDecEntity *parent);

/* Helper functions */
//MimeDecField * MimeDecFillField(MimeDecEntity *entity, const char *name,
//        uint32_t nlen, const char *value, uint32_t vlen, int copy_name_value);

/* Parser functions */
MimeDecParseState * MimeDecInitParser(void *data, int (*dcpfunc)(const uint8_t *chunk,
        uint32_t len, MimeDecParseState *state));
void MimeDecDeInitParser(MimeDecParseState *state);
int MimeDecParseComplete(MimeDecParseState *state);
int MimeDecParseLine(const uint8_t *line, const uint32_t len, const uint8_t delim_len, MimeDecParseState *state);
MimeDecEntity * MimeDecParseFullMsg(const uint8_t *buf, uint32_t blen, void *data,
        int (*DataChunkProcessorFunc)(const uint8_t *chunk, uint32_t len, MimeDecParseState *state));
const char *MimeDecParseStateGetStatus(MimeDecParseState *state);

/* Test functions */
void MimeDecRegisterTests(void);

#endif
