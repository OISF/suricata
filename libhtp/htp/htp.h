/*
 * LibHTP (http://www.libhtp.org)
 * Copyright 2009,2010 Ivan Ristic <ivanr@webkreator.com>
 *
 * LibHTP is an open source product, released under terms of the General Public Licence
 * version 2 (GPLv2). Please refer to the file LICENSE, which contains the complete text
 * of the license.
 *
 * In addition, there is a special exception that allows LibHTP to be freely
 * used with any OSI-approved open source licence. Please refer to the file
 * LIBHTP_LICENSING_EXCEPTION for the full text of the exception.
 *
 */

#ifndef _HTP_H
#define	_HTP_H

typedef struct htp_cfg_t htp_cfg_t;
typedef struct htp_conn_t htp_conn_t;
typedef struct htp_connp_t htp_connp_t;
typedef struct htp_header_t htp_header_t;
typedef struct htp_header_line_t htp_header_line_t;
typedef struct htp_log_t htp_log_t;
typedef struct htp_tx_data_t htp_tx_data_t;
typedef struct htp_tx_t htp_tx_t;
typedef struct htp_uri_t htp_uri_t;
typedef struct htp_urldecoder_t htp_urldecoder_t;

#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bstr.h"
#include "dslib.h"
#include "hooks.h"
#include "htp_decompressors.h"

// -- Defines -------------------------------------------------------------------------------------

#define HTP_BASE_VERSION_TEXT	"0.2.14"

#define HTP_ERROR              -1
#define HTP_OK                  0
#define HTP_DATA                1
#define HTP_DATA_OTHER          2
#define HTP_DECLINED            3

#define PROTOCOL_UNKNOWN        -1
#define HTTP_0_9                9
#define HTTP_1_0                100
#define HTTP_1_1                101

#define COMPRESSION_NONE        0
#define COMPRESSION_GZIP        1
#define COMPRESSION_COMPRESS    2 // Not implemented
#define COMPRESSION_DEFLATE     3 // Not implemented

#define HTP_LOG_MARK                __FILE__,__LINE__

#define HTP_LOG_ERROR               1
#define HTP_LOG_WARNING             2
#define HTP_LOG_NOTICE              3
#define HTP_LOG_INFO                4
#define HTP_LOG_DEBUG               5
#define HTP_LOG_DEBUG2              6

#define HTP_HEADER_MISSING_COLON            1
#define HTP_HEADER_INVALID_NAME             2
#define HTP_HEADER_LWS_AFTER_FIELD_NAME     3
#define HTP_LINE_TOO_LONG_HARD              4
#define HTP_LINE_TOO_LONG_SOFT              5

#define HTP_HEADER_LIMIT_HARD               18000
#define HTP_HEADER_LIMIT_SOFT               9000

#define LOG_NO_CODE             0

#define CR '\r'
#define LF '\n'

#define M_UNKNOWN              -1

// The following request method are defined in Apache 2.2.13, in httpd.h.
#define M_GET                   0
#define M_PUT                   1
#define M_POST                  2
#define M_DELETE                3
#define M_CONNECT               4
#define M_OPTIONS               5
#define M_TRACE                 6
#define M_PATCH                 7
#define M_PROPFIND              8
#define M_PROPPATCH             9
#define M_MKCOL                 10
#define M_COPY                  11
#define M_MOVE                  12
#define M_LOCK                  13
#define M_UNLOCK                14
#define M_VERSION_CONTROL       15
#define M_CHECKOUT              16
#define M_UNCHECKOUT            17
#define M_CHECKIN               18
#define M_UPDATE                19
#define M_LABEL                 20
#define M_REPORT                21
#define M_MKWORKSPACE           22
#define M_MKACTIVITY            23
#define M_BASELINE_CONTROL      24
#define M_MERGE                 25
#define M_INVALID               26

// Interestingly, Apache does not define M_HEAD
#define M_HEAD                  1000

#define HTP_FIELD_UNPARSEABLE           0x000001
#define HTP_FIELD_INVALID               0x000002
#define HTP_FIELD_FOLDED                0x000004
#define HTP_FIELD_REPEATED              0x000008
#define HTP_FIELD_LONG                  0x000010
#define HTP_FIELD_NUL_BYTE              0x000020
#define HTP_REQUEST_SMUGGLING           0x000040
#define HTP_INVALID_FOLDING             0x000080
#define HTP_INVALID_CHUNKING            0x000100
#define HTP_MULTI_PACKET_HEAD           0x000200
#define HTP_HOST_MISSING                0x000400
#define HTP_AMBIGUOUS_HOST              0x000800
#define HTP_PATH_ENCODED_NUL            0x001000
#define HTP_PATH_INVALID_ENCODING       0x002000
#define HTP_PATH_INVALID                0x004000
#define HTP_PATH_OVERLONG_U             0x008000
#define HTP_PATH_ENCODED_SEPARATOR      0x010000

#define HTP_PATH_UTF8_VALID             0x020000 /* At least one valid UTF-8 character and no invalid ones */
#define HTP_PATH_UTF8_INVALID           0x040000
#define HTP_PATH_UTF8_OVERLONG          0x080000
#define HTP_PATH_FULLWIDTH_EVASION      0x100000 /* Range U+FF00 - U+FFFF detected */

#define PIPELINED_CONNECTION        1

#define HTP_SERVER_MINIMAL          0
#define HTP_SERVER_GENERIC          1
#define HTP_SERVER_IDS              2
#define HTP_SERVER_IIS_4_0          4   /* Windows NT 4.0 */
#define HTP_SERVER_IIS_5_0          5   /* Windows 2000 */
#define HTP_SERVER_IIS_5_1          6   /* Windows XP Professional */
#define HTP_SERVER_IIS_6_0          7   /* Windows 2003 */
#define HTP_SERVER_IIS_7_0          8   /* Windows 2008 */
#define HTP_SERVER_IIS_7_5          9   /* Windows 7 */
#define HTP_SERVER_TOMCAT_6_0       10  /* Unused */
#define HTP_SERVER_APACHE           11
#define HTP_SERVER_APACHE_2_2       12

#define NONE                        0
#define IDENTITY                    1
#define CHUNKED                     2

#define TX_PROGRESS_NEW             0
#define TX_PROGRESS_REQ_LINE        1
#define TX_PROGRESS_REQ_HEADERS     2
#define TX_PROGRESS_REQ_BODY        3
#define TX_PROGRESS_REQ_TRAILER     4
#define TX_PROGRESS_WAIT            5
#define TX_PROGRESS_RES_LINE        6
#define TX_PROGRESS_RES_HEADERS     7
#define TX_PROGRESS_RES_BODY        8
#define TX_PROGRESS_RES_TRAILER     9
#define TX_PROGRESS_DONE            10

#define STREAM_STATE_NEW            0
#define STREAM_STATE_OPEN           1
#define STREAM_STATE_CLOSED         2
#define STREAM_STATE_ERROR          3
#define STREAM_STATE_TUNNEL         4
#define STREAM_STATE_DATA_OTHER     5
#define STREAM_STATE_DATA           9

#define URL_DECODER_PRESERVE_PERCENT            0
#define URL_DECODER_REMOVE_PERCENT              1
#define URL_DECODER_DECODE_INVALID              2
#define URL_DECODER_STATUS_400                  400

#define NONE        0
#define NO          0
#define BESTFIT     0
#define YES         1
#define TERMINATE   1
#define STATUS_400  400
#define STATUS_404  401

#define IN_TEST_NEXT_BYTE_OR_RETURN(X) \
if ((X)->in_current_offset >= (X)->in_current_len) { \
    return HTP_DATA; \
}

#define IN_NEXT_BYTE(X) \
if ((X)->in_current_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_offset]; \
    (X)->in_current_offset++; \
    (X)->in_stream_offset++; \
} else { \
    (X)->in_next_byte = -1; \
}

#define IN_NEXT_BYTE_OR_RETURN(X) \
if ((X)->in_current_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_offset]; \
    (X)->in_current_offset++; \
    (X)->in_stream_offset++; \
} else { \
    return HTP_DATA; \
}

#define IN_COPY_BYTE_OR_RETURN(X) \
if ((X)->in_current_offset < (X)->in_current_len) { \
    (X)->in_next_byte = (X)->in_current_data[(X)->in_current_offset]; \
    (X)->in_current_offset++; \
    (X)->in_stream_offset++; \
} else { \
    return HTP_DATA; \
} \
\
if ((X)->in_line_len < (X)->in_line_size) { \
    (X)->in_line[(X)->in_line_len] = (X)->in_next_byte; \
    (X)->in_line_len++; \
    if (((X)->in_line_len == HTP_HEADER_LIMIT_SOFT)&&(!((X)->in_tx->flags & HTP_FIELD_LONG))) { \
        (X)->in_tx->flags |= HTP_FIELD_LONG; \
        htp_log((X), HTP_LOG_MARK, HTP_LOG_ERROR, HTP_LINE_TOO_LONG_SOFT, "Request field over soft limit"); \
    } \
} else { \
    htp_log((X), HTP_LOG_MARK, HTP_LOG_ERROR, HTP_LINE_TOO_LONG_HARD, "Request field over hard limit"); \
    return HTP_ERROR; \
}

#define OUT_TEST_NEXT_BYTE_OR_RETURN(X) \
if ((X)->out_current_offset >= (X)->out_current_len) { \
    return HTP_DATA; \
}

#define OUT_NEXT_BYTE(X) \
if ((X)->out_current_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_offset]; \
    (X)->out_current_offset++; \
    (X)->out_stream_offset++; \
} else { \
    (X)->out_next_byte = -1; \
}

#define OUT_NEXT_BYTE_OR_RETURN(X) \
if ((X)->out_current_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_offset]; \
    (X)->out_current_offset++; \
    (X)->out_stream_offset++; \
} else { \
    return HTP_DATA; \
}

#define OUT_COPY_BYTE_OR_RETURN(X) \
if ((X)->out_current_offset < (X)->out_current_len) { \
    (X)->out_next_byte = (X)->out_current_data[(X)->out_current_offset]; \
    (X)->out_current_offset++; \
    (X)->out_stream_offset++; \
} else { \
    return HTP_DATA; \
} \
\
if ((X)->out_line_len < (X)->out_line_size) { \
    (X)->out_line[(X)->out_line_len] = (X)->out_next_byte; \
    (X)->out_line_len++; \
    if (((X)->out_line_len == HTP_HEADER_LIMIT_SOFT)&&(!((X)->out_tx->flags & HTP_FIELD_LONG))) { \
        (X)->out_tx->flags |= HTP_FIELD_LONG; \
        htp_log((X), HTP_LOG_MARK, HTP_LOG_ERROR, HTP_LINE_TOO_LONG_SOFT, "Response field over soft limit"); \
    } \
} else { \
    htp_log((X), HTP_LOG_MARK, HTP_LOG_ERROR, HTP_LINE_TOO_LONG_HARD, "Response field over hard limit"); \
    return HTP_ERROR; \
}

typedef uint32_t htp_time_t;

// -- Data structures -----------------------------------------------------------------------------

struct htp_cfg_t {
    /** Hard field limit length. If the parser encounters a line that's longer
     *  than this value it will give up parsing. Do note that the line limit
     *  is not the same thing as header length limit. Because of header folding,
     *  a header can end up being longer than the line limit.
     */
    size_t field_limit_hard;
    
    /** Soft field limit length. If this limit is reached the parser will issue
     *  a warning but continue to run.
     */
    size_t field_limit_soft;              

    /** Log level, which will be used when deciding whether to store or
     *  ignore the messages issued by the parser.
     */
    int log_level;   

    /**
     * Server personality ID.
     */
    int spersonality;

    /** The function used for request line parsing. Depends on the personality. */
    int (*parse_request_line)(htp_connp_t *connp);

    /** The function used for response line parsing. Depends on the personality. */
    int (*parse_response_line)(htp_connp_t *connp);

    /** The function used for request header parsing. Depends on the personality. */
    int (*process_request_header)(htp_connp_t *connp);

    /** The function used for response header parsing. Depends on the personality. */
    int (*process_response_header)(htp_connp_t *connp);

    
    // Path handling

    /** Should we treat backslash characters as path segment separators? */
    int path_backslash_separators;
    int query_backslash_separators;
    
    /** Should we treat paths as case insensitive? */
    int path_case_insensitive;
    int query_case_insensitive;

    /** Should we compress multiple path segment separators into one? */
    int path_compress_separators;
    int query_compress_separators;

    /** This parameter is used to predict how a server will react when control
     *  characters are present in a request path, but does not affect path
     *  normalization.
     */
    int path_control_char_handling;
    int query_control_char_handling;

    /** Should the parser convert UTF-8 into a single-byte stream, using
     *  best-fit?
     */
    int path_convert_utf8;

    /** Should we URL-decode encoded path segment separators? */
    int path_decode_separators;
    int query_decode_separators;

    /** Should we decode %u-encoded characters? */
    int path_decode_u_encoding;
    int query_decode_u_encoding;

    /** How do handle invalid encodings: URL_DECODER_LEAVE_PERCENT,
     *  URL_DECODER_REMOVE_PERCENT or URL_DECODER_DECODE_INVALID.
     */
    int path_invalid_encoding_handling;
    int query_invalid_encoding_handling;

    /** Controls how invalid UTF-8 characters are handled. */
    int path_invalid_utf8_handling;

    /** Controls how encoded NUL bytes are handled. */
    int path_nul_encoded_handling;
    int query_nul_encoded_handling;

    /** Controls how raw NUL bytes are handled. */
    int path_nul_raw_handling;
    int query_nul_raw_handling;

    /** The replacement character used when there is no best-fit mapping. */
    unsigned char path_replacement_char;

    /** How will the server handle UCS-2 characters? */
    int path_unicode_mapping;      

    /** XXX Unused */
    int path_utf8_overlong_handling;

    /** The best-fit map to use to decode %u-encoded characters. */
    unsigned char *path_u_bestfit_map;

    /** Whether to generate the request_uri_normalized field. */
    int generate_request_uri_normalized;


    // Hooks

    /** Transaction start hook, invoked when the parser receives the first
     *  byte of a new transaction.
     */
    htp_hook_t *hook_transaction_start;

    /** Request line hook, invoked after a request line has been parsed. */
    htp_hook_t *hook_request_line;

    /** Request URI normalization hook, for overriding default normalization of URI. */
    htp_hook_t *hook_request_uri_normalize;

    /** Request headers hook, invoked after all request headers are seen. */
    htp_hook_t *hook_request_headers;

    /** Request body data hook, invoked every time body data is available. Chunked data
     *  will be dechunked and compressed data will be decompressed (not implemented at present)
     *  before the data is passed to this hook.
     */
    htp_hook_t *hook_request_body_data;

    /** Request trailer hook, invoked after all trailer headers are seen,
     *  and if they are seen (not invoked otherwise).
     */
    htp_hook_t *hook_request_trailer;

    /** Request hook, invoked after a complete request is seen. */
    htp_hook_t *hook_request;

    /** Response line hook, invoked after a response line has been parsed. */
    htp_hook_t *hook_response_line;

    /** Response headers book, invoked after all response headers have been seen. */
    htp_hook_t *hook_response_headers;

    /** Response body data hook, invoked whenever a chunk of response data is available. Chunked
     *  data will be dechunked and compressed data will be decompressed (not implemented
     *  at present) before the data is passed to this hook.*/
    htp_hook_t *hook_response_body_data;

    /** Response trailer hook, invoked after all trailer headers have been processed,
     *  and only if the trailer exists.
     */
    htp_hook_t *hook_response_trailer;

    /** Response hook, invoked after a response has been seen. There isn't a separate
     *  transaction hook, use this hook to do something whenever a transaction is
     *  complete.
     */
    htp_hook_t *hook_response;

    /**
     * Log hook, invoked every time the library wants to log.
     */
    htp_hook_t *hook_log;

    /** Opaque user data associated with this configuration structure. */
    void *user_data;
};

struct htp_conn_t {
    /** Connection parser associated with this connection. */
    htp_connp_t *connp;

    /** Remote IP address. */
    char *remote_addr;

    /** Remote port. */
    int remote_port;

    /** Local IP address. */
    char *local_addr;

    /** Local port. */
    int local_port;

    /** Transactions carried out on this connection. The list may contain
     *  NULL elements when some of the transactions are deleted (and then
     *  removed from a connection by calling htp_conn_remove_tx().
     */
    list_t *transactions;

    /** Log messages associated with this connection. */
    list_t *messages;   

    /** Parsing flags: PIPELINED_CONNECTION. */
    unsigned int flags;   

    /** When was this connection opened? */
    htp_time_t open_timestamp;

    /** When was this connection closed? */
    htp_time_t close_timestamp;
    
    /** Inbound data counter. */
    size_t in_data_counter;

    /** Outbound data counter. */
    size_t out_data_counter;

    /** Inbound packet counter. */
    size_t in_packet_counter;

    /** Outbound packet counter. */
    size_t out_packet_counter;
};

struct htp_connp_t {
    // General fields
    
    /** Current parser configuration structure. */
    htp_cfg_t *cfg;

    /** Is the configuration structure only used with this connection
     *  parser? If it is, then it can be changed as parsing goes on,
     *  and destroyed along with the parser in the end.
     */
    int is_cfg_private;

    /** The connection structure associated with this parser. */
    htp_conn_t *conn;

    /** Opaque user data associated with this parser. */
    void *user_data;   

    /** On parser failure, this field will contain the error information. Do note, however,
     *  that the value in this field will only be valid immediately after an error condition,
     *  but it is not guaranteed to remain valid if the parser is invoked again.
     */
    htp_log_t *last_error;

    // Request parser fields

    /** Parser inbound status. Starts as HTP_OK, but may turn into HTP_ERROR. */
    unsigned int in_status;

    /** Parser output status. Starts as HTP_OK, but may turn into HTP_ERROR. */
    unsigned int out_status;

    /** The time when the last request data chunk was received. */
    htp_time_t in_timestamp;

    /** Pointer to the current request data chunk. */
    unsigned char *in_current_data;

    /** The length of the current request data chunk. */
    int64_t in_current_len;

    /** The offset of the next byte in the request data chunk to consume. */
    int64_t in_current_offset;

    /** How many data chunks does the inbound connection stream consist of? */
    size_t in_chunk_count;

    /** The index of the first chunk used in the current request. */
    size_t in_chunk_request_index;

    /** The offset, in the entire connection stream, of the next request byte. */
    int64_t in_stream_offset;

    /** The value of the request byte currently being processed. */
    int in_next_byte;

    /** Pointer to the request line buffer. */
    unsigned char *in_line;

    /** Size of the request line buffer. */
    size_t in_line_size;

    /** Lenght of the current request line. */
    size_t in_line_len;    

    /** Ongoing inbound transaction. */
    htp_tx_t *in_tx;   

    /** The request header line currently being processed. */
    htp_header_line_t *in_header_line;

    /** The index, in the structure holding all request header lines, of the
     *  line with which the current header begins. The header lines are
     *  kept in the transaction structure.
     */
    int in_header_line_index;

    /** How many lines are there in the current request header? */
    int in_header_line_counter;

    /**
     * The request body length declared in a valid request headers. The key here
     * is "valid". This field will not be populated if a request contains both
     * a Transfer-Encoding header and a Content-Lenght header.
     */
    int64_t in_content_length;

    /** Holds the remaining request body length that we expect to read. This
     *  field will be available only when the length of a request body is known
     *  in advance, i.e. when request headers contain a Content-Length header.
     */
    int64_t in_body_data_left;

    /** Holds the amount of data that needs to be read from the
     *  current data chunk. Only used with chunked request bodies.
     */
    int in_chunked_length;

    /** Current request parser state. */
    int (*in_state)(htp_connp_t *);

    // Response parser fields

    /** Response counter, incremented with every new response. This field is
     *  used to match responses to requests. The expectation is that for every
     *  response there will already be a transaction (request) waiting.
     */
    size_t out_next_tx_index;

    /** The time when the last response data chunk was received. */
    htp_time_t out_timestamp;

    /** Pointer to the current response data chunk. */
    unsigned char *out_current_data;

    /** The length of the current response data chunk. */
    int64_t out_current_len;

    /** The offset of the next byte in the response data chunk to consume. */
    int64_t out_current_offset;

    /** The offset, in the entire connection stream, of the next response byte. */
    int64_t out_stream_offset;

    /** The value of the response byte currently being processed. */
    int out_next_byte;

    /** Pointer to the response line buffer. */
    unsigned char *out_line;

    /** Size of the response line buffer. */
    size_t out_line_size;

    /** Lenght of the current response line. */
    size_t out_line_len;       
        
    /** Ongoing outbound transaction */
    htp_tx_t *out_tx;

    /** The response header line currently being processed. */
    htp_header_line_t *out_header_line;

    /** The index, in the structure holding all response header lines, of the
     *  line with which the current header begins. The header lines are
     *  kept in the transaction structure.
     */
    int out_header_line_index;

    /** How many lines are there in the current response header? */
    int out_header_line_counter;

    /**
     * The length of the current response body as presented in the
     * Content-Length response header.
     */
    int64_t out_content_length;

    /** The remaining length of the current response body, if known. */
    int64_t out_body_data_left;

    /** Holds the amount of data that needs to be read from the
     *  current response data chunk. Only used with chunked response bodies.
     */
    int out_chunked_length;

    /** Current response parser state. */
    int (*out_state)(htp_connp_t *);

    /** Response decompressor used to decompress response body data. */
    htp_decompressor_t *out_decompressor;
};

struct htp_log_t {
    /** The connection parser associated with this log message. */
    htp_connp_t *connp;

    /** The transaction associated with this log message, if any. */
    htp_tx_t *tx;

    /** Log message. */
    const char *msg;

    /** Message level. */
    int level;

    /** Message code. */
    int code;

    /** File in which the code that emitted the message resides. */
    const char *file;

    /** Line number on which the code that emitted the message resides. */
    unsigned int line;
};

struct htp_header_line_t {
    /** Header line data. */
    bstr *line;

    /** Offset at which header name begins, if applicable. */
    size_t name_offset;

    /** Header name length, if applicable. */
    size_t name_len;

    /** Offset at which header value begins, if applicable. */
    size_t value_offset;

    /** Value length, if applicable. */
    size_t value_len;

    /** How many NUL bytes are there on this header line? */
    unsigned int has_nulls;

    /** The offset of the first NUL byte, or -1. */
    int first_nul_offset;

    /** Parsing flags: HTP_FIELD_INVALID_NOT_FATAL, HTP_FIELD_INVALID_FATAL, HTP_FIELD_LONG */
    unsigned int flags;

    /** terminator characters, if NULL assume RFC compliant 0d 0a */
    bstr *terminators;

    /** Header that uses this line. */
    htp_header_t *header;
};

struct htp_header_t {
    /** Header name. */
    bstr *name;

    /** Header value. */
    bstr *value;   

    /** Parsing flags: HTP_FIELD_INVALID_NOT_FATAL, HTP_FIELD_FOLDED, HTP_FIELD_REPEATED */
    unsigned int flags;
};

struct htp_tx_t {
    /** The connection parsed associated with this transaction. */
    htp_connp_t *connp;

    /** The connection to which this transaction belongs. */
    htp_conn_t *conn;

    /** The configuration structure associated with this transaction. */
    htp_cfg_t *cfg;

    /** Is the configuration structure shared with other transactions or connections? As
     *  a rule of thumb transactions will initially share their configuration structure, but
     *  copy-on-write may be used when an attempt to modify configuration is detected.
     */
    int is_cfg_shared;

    /** The user data associated with this transaction. */
    void *user_data;
    
    // Request
    unsigned int request_ignored_lines;

    /** The first line of this request. */
    bstr *request_line;

    /** How many NUL bytes are there in the request line? */
    int request_line_nul;

    /** The offset of the first NUL byte. */
    int request_line_nul_offset;

    /** Request method. */
    bstr *request_method;

    /** Request method, as number. Available only if we were able to recognize the request method. */
    int request_method_number;

    /** Request URI, raw, as given to us on the request line. */
    bstr *request_uri;

    /**
     * Normalized request URI as a single string. The availability of this
     * field depends on configuration. Use htp_config_set_generate_request_uri_normalized()
     * to ask for the field to be generated.
     */
    bstr *request_uri_normalized;

    /** Request protocol, as text. */
    bstr *request_protocol;

    /** Protocol version as a number: -1 means unknown, 9 (HTTP_0_9) means 0.9,
     *  100 (HTTP_1_0) means 1.0 and 101 (HTTP_1_1) means 1.1.
     */
    int request_protocol_number;

    /** Is this request using a short-style HTTP/0.9 request? */
    int protocol_is_simple;   

    /** This structure holds a parsed request_uri, with the missing information
     *  added (e.g., adding port number from the TCP information) and the fields
     *  normalized. This structure should be used to make decisions about a request.
     *  To inspect raw data, either use request_uri, or parsed_uri_incomplete.
     */
    htp_uri_t *parsed_uri;

    /** This structure holds the individual components parsed out of the request URI. No
     *  attempt is made to normalize the contents or replace the missing pieces with
     *  defaults. The purpose of this field is to allow you to look at the data as it
     *  was supplied. Use parsed_uri when you need to act on data. Note that this field
     *  will never have the port as a number.
     */
    htp_uri_t *parsed_uri_incomplete;

    /** The actual message length (the length _after_ transformations
     *  have been applied). This field will change as a request body is being
     *  received, with the final value available once the entire body has
     *  been received.
     */
    size_t request_message_len;

    /** The actual entity length (the length _before_ transformations
     *  have been applied). This field will change as a request body is being
     *  received, with the final value available once the entire body has
     *  been received.
     */
    size_t request_entity_len;

    /** TODO The length of the data transmitted in a request body, minus the length
     *  of the files (if any). At worst, this field will be equal to the entity
     *  length if the entity encoding is not recognized. If we recognise the encoding
     *  (e.g., if it is application/x-www-form-urlencoded or multipart/form-data), the
     *  decoder may be able to separate the data from everything else, in which case
     *  the value in this field will be lower.
     */
    size_t request_nonfiledata_len;

    /** TODO The length of the files uploaded using multipart/form-data, or in a
     *  request that uses PUT (in which case this field will be equal to the
     *  entity length field). This field will be zero in all other cases.
     */
    size_t request_filedata_len;        

    /** Original request header lines. This list stores instances of htp_header_line_t. */
    list_t *request_header_lines;

    /** Parsed request headers. */
    table_t *request_headers;

    /** Contains raw request headers. This field is generated on demand, use
     *  htp_tx_get_request_headers_raw() to get it.
     */
    bstr *request_headers_raw;

    /** How many request header lines have been included in the raw
     *  buffer (above).
     */
    size_t request_headers_raw_lines;


    /** Request transfer coding: IDENTITY or CHUNKED. Only available on requests that have bodies. */
    int request_transfer_coding;

    /** Compression; currently COMPRESSION_NONE or COMPRESSION_GZIP. */
    int request_content_encoding;

    // Response

    /** How many empty lines did we ignore before reaching the status line? */
    unsigned int response_ignored_lines;

    /** Response line. */
    bstr *response_line;

    /** Response protocol, as text. */
    bstr *response_protocol;

    /** Response protocol as number. Only available if we were
     *  able to parse the protocol version.
     */
    int response_protocol_number;

    /** Response status code, as text. */
    bstr *response_status;

    /** Reponse status code, available only if we were able to parse it. */
    int response_status_number;

    /** This field is set by the protocol decoder with it thinks that the
     *  backend server will reject a request with a particular status code.
     */
    int response_status_expected_number;

    /** The message associated with the response status code. */
    bstr *response_message;

    /** Have we seen the server respond with a 100 response? */
    int seen_100continue;   

    /** Original response header lines. */
    list_t *response_header_lines;

    /** Parsed response headers. */
    table_t *response_headers;

    /** Contains raw response headers. This field is generated on demand, use
     *  htp_tx_get_response_headers_raw() to get it.
     */
    bstr *response_headers_raw;

    /** How many response header lines have been included in the raw
     *  buffer (above).
     */
    size_t response_headers_raw_lines;

    /** The actual message length (the length _after_ transformations
     *  have been applied). This field will change as a request body is being
     *  received, with the final value available once the entire body has
     *  been received.
     */
    size_t response_message_len;

    /** The actual entity length (the length _before_ transformations
     *  have been applied). This field will change as a request body is being
     *  received, with the final value available once the entire body has
     *  been received.
     */
    size_t response_entity_len;

    /** Response transfer coding: IDENTITY or CHUNKED. Only available on responses that have bodies. */
    int response_transfer_coding;

    /** Compression; currently COMPRESSION_NONE or COMPRESSION_GZIP. */
    int response_content_encoding;   
    
    // Common

    /** Parsing flags: HTP_INVALID_CHUNKING, HTP_INVALID_FOLDING,
     *  HTP_REQUEST_SMUGGLING, HTP_MULTI_PACKET_HEAD.
     */
    unsigned int flags;

    /** Transaction progress. Look for the TX_PROGRESS_* constants for more information. */
    unsigned int progress;
};

/** This structure is used to pass transaction data to callbacks. */
struct htp_tx_data_t {
    /** Transaction pointer. */
    htp_tx_t *tx;

    /** Pointer to the data buffer. */
    unsigned char *data;

    /** Buffer length. */
    size_t len;
};

/** URI structure. Each of the fields provides access to a single
 *  URI element. A typical URI will look like this:
 *  http://username:password@hostname.com:8080/path?query#fragment.
 */
struct htp_uri_t {
    /** Scheme */
    bstr *scheme;

    /** Username */
    bstr *username;

    /** Password */
    bstr *password;

    /** Hostname */
    bstr *hostname;

    /** Port, as string */
    bstr *port;

    /** Port, as number, but only if the port is valid. */
      int port_number;

    /** The path part of this URI */
    bstr *path;

    /** Query string */
    bstr *query;

    /** Fragment identifier */
    bstr *fragment;
};

// -- Functions -----------------------------------------------------------------------------------

const char *htp_get_version();

htp_cfg_t *htp_config_copy(htp_cfg_t *cfg);
htp_cfg_t *htp_config_create();
      void htp_config_destroy(htp_cfg_t *cfg); 

void htp_config_register_transaction_start(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_request_line(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_request_uri_normalize(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_request_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_request_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));
void htp_config_register_request_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_request(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));

void htp_config_register_response_line(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_response_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_response_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *));
void htp_config_register_response_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));
void htp_config_register_response(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *));

void htp_config_register_log(htp_cfg_t *cfg, int (*callback_fn)(htp_log_t *));

 int htp_config_set_server_personality(htp_cfg_t *cfg, int personality);

void htp_config_set_bestfit_map(htp_cfg_t *cfg, unsigned char *map);
void htp_config_set_path_backslash_separators(htp_cfg_t *cfg, int backslash_separators);
void htp_config_set_query_backslash_separators(htp_cfg_t *cfg, int backslash_separators);
void htp_config_set_path_case_insensitive(htp_cfg_t *cfg, int path_case_insensitive);
void htp_config_set_query_case_insensitive(htp_cfg_t *cfg, int case_insensitive);
void htp_config_set_path_compress_separators(htp_cfg_t *cfg, int compress_separators);
void htp_config_set_query_compress_separators(htp_cfg_t *cfg, int compress_separators);
void htp_config_set_path_control_char_handling(htp_cfg_t *cfg, int control_char_handling);
void htp_config_set_query_control_char_handling(htp_cfg_t *cfg, int control_char_handling);
void htp_config_set_path_convert_utf8(htp_cfg_t *cfg, int convert_utf8);
void htp_config_set_path_decode_separators(htp_cfg_t *cfg, int backslash_separators);
void htp_config_set_query_decode_separators(htp_cfg_t *cfg, int decode_separators);
void htp_config_set_path_decode_u_encoding(htp_cfg_t *cfg, int decode_u_encoding);
void htp_config_set_query_decode_u_encoding(htp_cfg_t *cfg, int decode_u_encoding);
void htp_config_set_path_invalid_encoding_handling(htp_cfg_t *cfg, int invalid_encoding_handling);
void htp_config_set_query_invalid_encoding_handling(htp_cfg_t *cfg, int invalid_encoding_handling);
void htp_config_set_path_invalid_utf8_handling(htp_cfg_t *cfg, int invalid_utf8_handling);
void htp_config_set_path_nul_encoded_handling(htp_cfg_t *cfg, int nul_encoded_handling);
void htp_config_set_query_nul_encoded_handling(htp_cfg_t *cfg, int nul_encoded_handling);
void htp_config_set_path_nul_raw_handling(htp_cfg_t *cfg, int nul_raw_handling);
void htp_config_set_query_nul_raw_handling(htp_cfg_t *cfg, int nul_raw_handling);
void htp_config_set_path_replacement_char(htp_cfg_t *cfg, int replacement_char);
void htp_config_set_path_unicode_mapping(htp_cfg_t *cfg, int unicode_mapping);

void htp_config_set_generate_request_uri_normalized(htp_cfg_t *cfg, int generate);


htp_connp_t *htp_connp_create(htp_cfg_t *cfg);
htp_connp_t *htp_connp_create_copycfg(htp_cfg_t *cfg);
void htp_connp_open(htp_connp_t *connp, const char *remote_addr, int remote_port, const char *local_addr, int local_port, htp_time_t timestamp);
void htp_connp_close(htp_connp_t *connp, htp_time_t timestamp);
void htp_connp_destroy(htp_connp_t *connp);
void htp_connp_destroy_all(htp_connp_t *connp);

 void htp_connp_set_user_data(htp_connp_t *connp, void *user_data);
void *htp_connp_get_user_data(htp_connp_t *connp);

htp_conn_t *htp_conn_create(htp_connp_t *connp);
       void htp_conn_destroy(htp_conn_t *conn);
        int htp_conn_remove_tx(htp_conn_t *conn, htp_tx_t *tx);

   int htp_connp_req_data(htp_connp_t *connp, htp_time_t timestamp, unsigned char *data, size_t len);
size_t htp_connp_req_data_consumed(htp_connp_t *connp);
   int htp_connp_res_data(htp_connp_t *connp, htp_time_t timestamp, unsigned char *data, size_t len);
size_t htp_connp_res_data_consumed(htp_connp_t *connp);

      void htp_connp_clear_error(htp_connp_t *connp);
htp_log_t *htp_connp_get_last_error(htp_connp_t *connp);

htp_header_t *htp_connp_header_parse(htp_connp_t *, unsigned char *, size_t);

#define CFG_NOT_SHARED  0
#define CFG_SHARED      1

htp_tx_t *htp_tx_create(htp_cfg_t *cfg, int is_cfg_shared, htp_conn_t *conn);
     void htp_tx_destroy(htp_tx_t *tx);
     void htp_tx_set_config(htp_tx_t *tx, htp_cfg_t *cfg, int is_cfg_shared);

     void htp_tx_set_user_data(htp_tx_t *tx, void *user_data);
    void *htp_tx_get_user_data(htp_tx_t *tx);

    bstr *htp_tx_get_request_uri_normalized(htp_tx_t *tx);

// Parsing functions

int htp_parse_request_line_generic(htp_connp_t *connp);
int htp_parse_request_header_generic(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len);
int htp_process_request_header_generic(htp_connp_t *);

int htp_parse_request_header_apache_2_2(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len);
int htp_parse_request_line_apache_2_2(htp_connp_t *connp);
int htp_process_request_header_apache_2_2(htp_connp_t *);

int htp_parse_response_line_generic(htp_connp_t *connp);
int htp_process_response_header_generic(htp_connp_t *connp);

// Parser states

int htp_connp_REQ_IDLE(htp_connp_t *connp);
int htp_connp_REQ_LINE(htp_connp_t *connp);
int htp_connp_REQ_PROTOCOL(htp_connp_t *connp);
int htp_connp_REQ_HEADERS(htp_connp_t *connp);
int htp_connp_REQ_BODY_DETERMINE(htp_connp_t *connp);
int htp_connp_REQ_BODY_IDENTITY(htp_connp_t *connp);
int htp_connp_REQ_BODY_CHUNKED_LENGTH(htp_connp_t *connp);
int htp_connp_REQ_BODY_CHUNKED_DATA(htp_connp_t *connp);
int htp_connp_REQ_BODY_CHUNKED_DATA_END(htp_connp_t *connp);

int htp_connp_REQ_CONNECT_CHECK(htp_connp_t *connp);
int htp_connp_REQ_CONNECT_WAIT_RESPONSE(htp_connp_t *connp);

int htp_connp_RES_IDLE(htp_connp_t *connp);
int htp_connp_RES_LINE(htp_connp_t *connp);
int htp_connp_RES_HEADERS(htp_connp_t *connp);
int htp_connp_RES_BODY_DETERMINE(htp_connp_t *connp);
int htp_connp_RES_BODY_IDENTITY(htp_connp_t *connp);
int htp_connp_RES_BODY_CHUNKED_LENGTH(htp_connp_t *connp);
int htp_connp_RES_BODY_CHUNKED_DATA(htp_connp_t *connp);
int htp_connp_RES_BODY_CHUNKED_DATA_END(htp_connp_t *connp);

// Utility functions

int htp_convert_method_to_number(bstr *);
int htp_is_lws(int c);
int htp_is_separator(int c);
int htp_is_text(int c);
int htp_is_token(int c);
int htp_chomp(unsigned char *data, size_t *len);
int htp_is_space(int c);

int htp_parse_protocol(bstr *protocol);

int htp_is_line_empty(unsigned char *data, size_t len);
int htp_is_line_whitespace(unsigned char *data, size_t len);

int htp_connp_is_line_folded(unsigned char *data, size_t len);
int htp_connp_is_line_terminator(htp_connp_t *connp, unsigned char *data, size_t len);
int htp_connp_is_line_ignorable(htp_connp_t *connp, unsigned char *data, size_t len);

int htp_parse_uri(bstr *input, htp_uri_t **uri);
int htp_parse_authority(htp_connp_t *connp, bstr *input, htp_uri_t **uri);
int htp_normalize_parsed_uri(htp_connp_t *connp, htp_uri_t *parsed_uri_incomplete, htp_uri_t *parsed_uri);
bstr *htp_normalize_hostname_inplace(bstr *input);
void htp_replace_hostname(htp_connp_t *connp, htp_uri_t *parsed_uri, bstr *hostname);

int htp_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path);
int htp_decode_query_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path);

void htp_uriencoding_normalize_inplace(bstr *s);

 int htp_prenormalize_uri_path_inplace(bstr *s, int *flags, int case_insensitive, int backslash, int decode_separators, int remove_consecutive);
void htp_normalize_uri_path_inplace(bstr *s);

void htp_utf8_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path);
void htp_utf8_validate_path(htp_tx_t *tx, bstr *path);

int htp_parse_content_length(bstr *b);
int htp_parse_chunked_length(unsigned char *data, size_t len);
int htp_parse_positive_integer_whitespace(unsigned char *data, size_t len, int base);
int htp_parse_status(bstr *status);

void htp_log(htp_connp_t *connp, const char *file, int line, int level, int code, const char *fmt, ...);
void htp_print_log(FILE *stream, htp_log_t *log);

void fprint_raw_data(FILE *stream, const char *name, unsigned char *data, size_t len);

char *htp_connp_in_state_as_string(htp_connp_t *connp);
char *htp_connp_out_state_as_string(htp_connp_t *connp);
char *htp_tx_progress_as_string(htp_tx_t *tx);

bstr *htp_unparse_uri_noencode(htp_uri_t *uri);

bstr *htp_tx_get_request_headers_raw(htp_tx_t *tx);
bstr *htp_tx_get_response_headers_raw(htp_tx_t *tx);

#endif	/* _HTP_H */


