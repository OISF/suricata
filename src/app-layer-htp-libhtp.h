/*
 * We are using this file to hold APIs copied from libhtp 0.5.x.
 */

/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * APIs from libhtp 0.5.x.
 */

#ifndef SURICATA_APP_LAYER_HTP_LIBHTP__H
#define SURICATA_APP_LAYER_HTP_LIBHTP__H

#include "suricata-common.h"

// Temporary alias definitions before switching to libhtp rust
#define HTP_STATUS_OK    HTP_OK
#define HTP_STATUS_ERROR HTP_ERROR

#define HTP_SERVER_PERSONALITY_APACHE_2 HTP_SERVER_APACHE_2
#define HTP_SERVER_PERSONALITY_MINIMAL  HTP_SERVER_MINIMAL
#define HTP_SERVER_PERSONALITY_GENERIC  HTP_SERVER_GENERIC
#define HTP_SERVER_PERSONALITY_IDS      HTP_SERVER_IDS
#define HTP_SERVER_PERSONALITY_IIS_4_0  HTP_SERVER_IIS_4_0
#define HTP_SERVER_PERSONALITY_IIS_5_0  HTP_SERVER_IIS_5_0
#define HTP_SERVER_PERSONALITY_IIS_5_1  HTP_SERVER_IIS_5_1
#define HTP_SERVER_PERSONALITY_IIS_6_0  HTP_SERVER_IIS_6_0
#define HTP_SERVER_PERSONALITY_IIS_7_0  HTP_SERVER_IIS_7_0
#define HTP_SERVER_PERSONALITY_IIS_7_5  HTP_SERVER_IIS_7_5

#define HTP_FLAGS_REQUEST_INVALID_T_E HTP_REQUEST_INVALID_T_E
#define HTP_FLAGS_REQUEST_INVALID_C_L HTP_REQUEST_INVALID_C_L
#define HTP_FLAGS_HOST_MISSING        HTP_HOST_MISSING
#define HTP_FLAGS_HOST_AMBIGUOUS      HTP_HOST_AMBIGUOUS
#define HTP_FLAGS_HOSTU_INVALID       HTP_HOSTU_INVALID
#define HTP_FLAGS_HOSTH_INVALID       HTP_HOSTH_INVALID

#define HTP_AUTH_TYPE_UNRECOGNIZED HTP_AUTH_UNRECOGNIZED

#define HTP_METHOD_UNKNOWN HTP_M_UNKNOWN
#define HTP_METHOD_GET     HTP_M_GET
#define HTP_METHOD_POST    HTP_M_POST
#define HTP_METHOD_PUT     HTP_M_PUT
#define HTP_METHOD_CONNECT HTP_M_CONNECT

#define HTP_STREAM_STATE_ERROR  HTP_STREAM_ERROR
#define HTP_STREAM_STATE_TUNNEL HTP_STREAM_TUNNEL

#define HTP_PROTOCOL_V1_1 HTP_PROTOCOL_1_1
#define HTP_PROTOCOL_V1_0 HTP_PROTOCOL_1_0
#define HTP_PROTOCOL_V0_9 HTP_PROTOCOL_0_9

#define HTP_REQUEST_PROGRESS_LINE      HTP_REQUEST_LINE
#define HTP_REQUEST_PROGRESS_HEADERS   HTP_REQUEST_HEADERS
#define HTP_REQUEST_PROGRESS_BODY      HTP_REQUEST_BODY
#define HTP_REQUEST_PROGRESS_TRAILER   HTP_REQUEST_TRAILER
#define HTP_REQUEST_PROGRESS_COMPLETE  HTP_REQUEST_COMPLETE
#define HTP_RESPONSE_PROGRESS_LINE     HTP_RESPONSE_LINE
#define HTP_RESPONSE_PROGRESS_HEADERS  HTP_RESPONSE_HEADERS
#define HTP_RESPONSE_PROGRESS_BODY     HTP_RESPONSE_BODY
#define HTP_RESPONSE_PROGRESS_TRAILER  HTP_RESPONSE_TRAILER
#define HTP_RESPONSE_PROGRESS_COMPLETE HTP_RESPONSE_COMPLETE

#define HTP_LOG_CODE_UNKNOWN                      HTTP_DECODER_EVENT_UNKNOWN_ERROR
#define HTP_LOG_CODE_GZIP_DECOMPRESSION_FAILED    HTTP_DECODER_EVENT_GZIP_DECOMPRESSION_FAILED
#define HTP_LOG_CODE_REQUEST_FIELD_MISSING_COLON  HTTP_DECODER_EVENT_REQUEST_FIELD_MISSING_COLON
#define HTP_LOG_CODE_RESPONSE_FIELD_MISSING_COLON HTTP_DECODER_EVENT_RESPONSE_FIELD_MISSING_COLON
#define HTP_LOG_CODE_INVALID_REQUEST_CHUNK_LEN    HTTP_DECODER_EVENT_INVALID_REQUEST_CHUNK_LEN
#define HTP_LOG_CODE_INVALID_RESPONSE_CHUNK_LEN   HTTP_DECODER_EVENT_INVALID_RESPONSE_CHUNK_LEN
#define HTP_LOG_CODE_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST                                    \
    HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST
#define HTP_LOG_CODE_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE                                   \
    HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE
#define HTP_LOG_CODE_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST                                       \
    HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST
#define HTP_LOG_CODE_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE                                      \
    HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE
#define HTP_LOG_CODE_DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST                                     \
    HTTP_DECODER_EVENT_DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST
#define HTP_LOG_CODE_DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE                                    \
    HTTP_DECODER_EVENT_DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE
#define HTP_LOG_CODE_CONTINUE_ALREADY_SEEN HTTP_DECODER_EVENT_100_CONTINUE_ALREADY_SEEN
#define HTP_LOG_CODE_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST                                           \
    HTTP_DECODER_EVENT_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST
#define HTP_LOG_CODE_INVALID_SERVER_PORT_IN_REQUEST                                                \
    HTTP_DECODER_EVENT_INVALID_SERVER_PORT_IN_REQUEST
#define HTP_LOG_CODE_INVALID_AUTHORITY_PORT        HTTP_DECODER_EVENT_INVALID_AUTHORITY_PORT
#define HTP_LOG_CODE_REQUEST_HEADER_INVALID        HTTP_DECODER_EVENT_REQUEST_HEADER_INVALID
#define HTP_LOG_CODE_RESPONSE_HEADER_INVALID       HTTP_DECODER_EVENT_RESPONSE_HEADER_INVALID
#define HTP_LOG_CODE_MISSING_HOST_HEADER           HTTP_DECODER_EVENT_MISSING_HOST_HEADER
#define HTP_LOG_CODE_HOST_HEADER_AMBIGUOUS         HTTP_DECODER_EVENT_HOST_HEADER_AMBIGUOUS
#define HTP_LOG_CODE_INVALID_REQUEST_FIELD_FOLDING HTTP_DECODER_EVENT_INVALID_REQUEST_FIELD_FOLDING
#define HTP_LOG_CODE_INVALID_RESPONSE_FIELD_FOLDING                                                \
    HTTP_DECODER_EVENT_INVALID_RESPONSE_FIELD_FOLDING
#define HTP_LOG_CODE_REQUEST_FIELD_TOO_LONG  HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG
#define HTP_LOG_CODE_RESPONSE_FIELD_TOO_LONG HTTP_DECODER_EVENT_RESPONSE_FIELD_TOO_LONG
#define HTP_LOG_CODE_FILE_NAME_TOO_LONG      HTTP_DECODER_EVENT_FILE_NAME_TOO_LONG
#define HTP_LOG_CODE_REQUEST_LINE_INVALID    HTTP_DECODER_EVENT_REQUEST_LINE_INVALID
#define HTP_LOG_CODE_REQUEST_BODY_UNEXPECTED HTTP_DECODER_EVENT_REQUEST_BODY_UNEXPECTED
#define HTP_LOG_CODE_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH                                         \
    HTTP_DECODER_EVENT_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH
#define HTP_LOG_CODE_URI_HOST_INVALID           HTTP_DECODER_EVENT_URI_HOST_INVALID
#define HTP_LOG_CODE_HEADER_HOST_INVALID        HTTP_DECODER_EVENT_HEADER_HOST_INVALID
#define HTP_LOG_CODE_AUTH_UNRECOGNIZED          HTTP_DECODER_EVENT_AUTH_UNRECOGNIZED
#define HTP_LOG_CODE_REQUEST_HEADER_REPETITION  HTTP_DECODER_EVENT_REQUEST_HEADER_REPETITION
#define HTP_LOG_CODE_RESPONSE_HEADER_REPETITION HTTP_DECODER_EVENT_RESPONSE_HEADER_REPETITION
#define HTP_LOG_CODE_DOUBLE_ENCODED_URI         HTTP_DECODER_EVENT_DOUBLE_ENCODED_URI
#define HTP_LOG_CODE_URI_DELIM_NON_COMPLIANT    HTTP_DECODER_EVENT_URI_DELIM_NON_COMPLIANT
#define HTP_LOG_CODE_METHOD_DELIM_NON_COMPLIANT HTTP_DECODER_EVENT_METHOD_DELIM_NON_COMPLIANT
#define HTP_LOG_CODE_REQUEST_LINE_LEADING_WHITESPACE                                               \
    HTTP_DECODER_EVENT_REQUEST_LINE_LEADING_WHITESPACE
#define HTP_LOG_CODE_TOO_MANY_ENCODING_LAYERS      HTTP_DECODER_EVENT_TOO_MANY_ENCODING_LAYERS
#define HTP_LOG_CODE_ABNORMAL_CE_HEADER            HTTP_DECODER_EVENT_ABNORMAL_CE_HEADER
#define HTP_LOG_CODE_RESPONSE_MULTIPART_BYTERANGES HTTP_DECODER_EVENT_RESPONSE_MULTIPART_BYTERANGES
#define HTP_LOG_CODE_RESPONSE_ABNORMAL_TRANSFER_ENCODING                                           \
    HTTP_DECODER_EVENT_RESPONSE_ABNORMAL_TRANSFER_ENCODING
#define HTP_LOG_CODE_RESPONSE_CHUNKED_OLD_PROTO HTTP_DECODER_EVENT_RESPONSE_CHUNKED_OLD_PROTO
#define HTP_LOG_CODE_RESPONSE_INVALID_PROTOCOL  HTTP_DECODER_EVENT_RESPONSE_INVALID_PROTOCOL
#define HTP_LOG_CODE_RESPONSE_INVALID_STATUS    HTTP_DECODER_EVENT_RESPONSE_INVALID_STATUS
#define HTP_LOG_CODE_REQUEST_LINE_INCOMPLETE    HTTP_DECODER_EVENT_REQUEST_LINE_INCOMPLETE
#define HTP_LOG_CODE_LZMA_MEMLIMIT_REACHED      HTTP_DECODER_EVENT_LZMA_MEMLIMIT_REACHED
#define HTP_LOG_CODE_COMPRESSION_BOMB           HTTP_DECODER_EVENT_COMPRESSION_BOMB

// Functions introduced to handle opaque htp_tx_t
#define htp_tx_flags(tx)                    tx->flags
#define htp_tx_is_protocol_0_9(tx)          tx->is_protocol_0_9
#define htp_tx_request_auth_type(tx)        tx->request_auth_type
#define htp_tx_request_hostname(tx)         tx->request_hostname
#define htp_tx_request_line(tx)             tx->request_line
#define htp_tx_request_message_len(tx)      tx->request_message_len
#define htp_tx_request_method(tx)           tx->request_method
#define htp_tx_request_method_number(tx)    tx->request_method_number
#define htp_tx_request_port_number(tx)      tx->request_port_number
#define htp_tx_request_progress(tx)         tx->request_progress
#define htp_tx_request_protocol(tx)         tx->request_protocol
#define htp_tx_request_protocol_number(tx)  tx->request_protocol_number
#define htp_tx_request_uri(tx)              tx->request_uri
#define htp_tx_request_headers(tx)          tx->request_headers
#define htp_tx_response_headers(tx)         tx->response_headers
#define htp_tx_response_protocol(tx)        tx->response_protocol
#define htp_tx_response_line(tx)            tx->response_line
#define htp_tx_response_message(tx)         tx->response_message
#define htp_tx_response_message_len(tx)     tx->response_message_len
#define htp_tx_response_status(tx)          tx->response_status
#define htp_tx_response_status_number(tx)   tx->response_status_number
#define htp_tx_response_progress(tx)        tx->response_progress
#define htp_tx_response_protocol_number(tx) tx->response_protocol_number

#define htp_tx_request_header(tx, header)  htp_table_get_c(tx->request_headers, header)
#define htp_tx_response_header(tx, header) htp_table_get_c(tx->response_headers, header)

// Functions introduced to handle opaque htp_header_t
#define htp_header_name_len(h)  bstr_len(h->name)
#define htp_header_name_ptr(h)  bstr_ptr(h->name)
#define htp_header_name(h)      h->name
#define htp_header_value_len(h) bstr_len(h->value)
#define htp_header_value_ptr(h) bstr_ptr(h->value)
#define htp_header_value(h)     h->value

// Functions introduced to handle opaque htp_headers_t:
#define htp_headers_size(headers)             htp_table_size(headers)
#define htp_headers_get_index(headers, index) htp_table_get_index(headers, index, NULL)
#define htp_tx_request_headers_size(tx)       htp_table_size(tx->request_headers)
#define htp_tx_request_header_index(tx, i)    htp_table_get_index(tx->request_headers, i, NULL);
#define htp_headers_t                         htp_table_t

// Functions introduced to handle opaque htp_tx_data_t:
#define htp_tx_data_len(d)  d->len
#define htp_tx_data_data(d) d->data
#define htp_tx_data_tx(d)   d->tx

// Functions introduced to handle opaque htp_conn_t:
#define htp_conn_request_data_counter(c)  c->in_data_counter
#define htp_conn_response_data_counter(c) c->out_data_counter

bstr *SCHTPGenerateNormalizedUri(htp_tx_t *tx, htp_uri_t *uri, bool uri_include_all);

#endif /* SURICATA_APP_LAYER_HTP_LIBHTP__H */
