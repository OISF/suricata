/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Helper api for retrieving values from a data stream.  To use the API
 * first create a new parsing context using StreamingParserNewContext().
 * To free the context use StreamingParserFreeContext().  Once a new
 * parser has been obtained, set a data stream that the context would
 * use for all future data retrieval.  You can do this by using
 * StreamingParserSetData().
 *
 * The API contains 4 sets of functions - 2 sets of test functions and
 * 2 sets of get functions.
 *
 * To retrieve values, use the StreamingParserGet*() function calls.
 * To test values without consuming the bytes in the stream, use the
 * StreamingParserTest*() calls.
 *
 * For every successful return of the value demanded by the client,
 * the api returns STREAMING_PARSER_ROK.
 * If the data stream supplied to the context gets exhausted, the api
 * returns STREAMING_PARSER_RDATA, indicating that it needs more data.
 *
 * Of the 2 sets of test functions, once set is the generic local
 * endianness one and the other has each endian(big and little)
 * specific calls.  The same applies to the Get*() functions.
 *
 * Note: For cases where you first try to retrieve a value using Test(
 * and the api demands more data(RDATA), and you follow it up with a call
 * (Test or Get) with a byte-order different from the first call, you'd
 * see junk being returned.
 */

#ifndef __UTIL_STREAMING_PARSER_H__
#define __UTIL_STREAMING_PARSER_H__

/* the return values for the API */
#define STREAMING_PARSER_RFAIL -1
#define STREAMING_PARSER_ROK 0
#define STREAMING_PARSER_RDATA 1

/* BO - Byte order */
#define STREAMING_PARSER_BO_LITTLE_ENDIAN 0
#define STREAMING_PARSER_BO_BIG_ENDIAN 1

/**
 * \brief Retrives a new streaming parser context.  All future API calls
 *        requires the client to supply this context.
 *
 * \retval Non-NULL pointer to the context if successfully created; NULL otherwise.
 */
void *StreamingParserNewContext(void);

/**
 * \brief Frees the context returned by StreamingParserNewContext().
 */
void StreamingParserFreeContext(void *ctx);

/**
 * \brief Sets the data to be used by the streaming parser.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param data_input The data stream.
 * \param data_input_len Length of the above data stream.
 */
void StreamingParserSetData(void *ctx, uint8_t *data, uint16_t data_len);

/*****Get functions*****/

/**
 * \brief Gets the next unsigned byte from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU8(void *ctx, uint8_t *ret_input);

/**
 * \brief Gets the next signed byte from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI8(void *ctx, int8_t *ret_input);

/**
 * \brief Gets the next uint16_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU16(void *ctx, uint16_t *ret_input);

/**
 * \brief Gets the next int16_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI16(void *ctx, int16_t *ret_input);

/**
 * \brief Gets the next uint32_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU32(void *ctx, uint32_t *ret_input);

/**
 * \brief Gets the next int32_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI32(void *ctx, int32_t *ret_input);

/**
 * \brief Gets the next uint64_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU64(void *ctx, uint64_t *ret_input);

/**
 * \brief Gets the next int64_t from the stream.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI64(void *ctx, int64_t *ret_input);


/*****Byte order specific Get functions*****/

/**
 * \brief Same as StreamingParserGetU16(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetU16().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserGetI16(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetI16().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserGetU32(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetU32().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserGetI32(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetI32().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserGetU64(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetU64().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserGetI64(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserGetI64().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserGetI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo);


/*****Test functions*****/

/**
 * \brief Gets the next unsigned byte from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU8(void *ctx, uint8_t *ret_input);

/**
 * \brief Gets the next signed byte from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI8(void *ctx, int8_t *ret_input);

/**
 * \brief Gets the next uint16_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU16(void *ctx, uint16_t *ret_input);

/**
 * \brief Gets the next int16_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.

 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI16(void *ctx, int16_t *ret_input);

/**
 * \brief Gets the next uint32_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU32(void *ctx, uint32_t *ret_input);

/**
 * \brief Gets the next int32_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI32(void *ctx, int32_t *ret_input);

/**
 * \brief Gets the next uint64_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU64(void *ctx, uint64_t *ret_input);

/**
 * \brief Gets the next int64_t from the stream, but doesn't
 *        consume it.  To understand what this means wrt a Get function
 *        and to understand Test* function calls have a look at the
 *        explanation at the top of this file.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param ret_input Pointer to the var to return the value back in.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI64(void *ctx, int64_t *ret_input);


/*****Byte order specific Test functions*****/

/**
 * \brief Same as StreamingParserTestU16(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestU16().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserTestI16(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestI16().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserTestU32(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestU32().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserTestI32(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestI32().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserTestU64(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestU64().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo);

/**
 * \brief Same as StreamingParserTestI64(), except that this accepts an
 *        extra argument that specifies the byte order to use.
 *        Only the extra param "bo" is explained here.  To understand
 *        rest of the params and retval, please have a look at the
 *        doc for StreamingParserTestI64().
 *
 * \param ctx Pointer to the streaming parser context.
 * \param bo The byte order to use.  Accepted values are
 *           STREAMING_PARSER_BO_LITTLE_ENDIAN and
 *           STREAMING_PARSER_BO_BIG_ENDIAN.
 *
 * \retval STREAMING_PARSER_ROK, if the value has been returned back;
 *         STREAMING_PARSER_RDATA, if the parser needs more data to
 *         return back the said value.
 */
int StreamingParserTestI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo);


/*****Chunk Retrieval*****/

/**
 * \brief Copies a chunk of data into the buffer supplied by the user.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param buffer Non-NULL buffer supplied by the user to copy the chunk into.
 * \param copy No of bytes to copy.
 * \param copied Pointer to var that would be updated by the API to indicate
 *               the no of bytes copied.
 *
 * \retval STREAMING_PARSER_ROK, if the "copy" value specified by the user
 *         has been written into the buffer.
 *         STREAMING_PARSER_RDATA, if there wasn't sufficient data to write
 *         into the bufffer.  In such a case the API would write available
 *         data into the buffer and the user can check the no of bytes
 *         written through the "copied" argument supplied.
 */
int StreamingParserGetChunk(void *ctx, uint8_t *buffer, uint16_t copy, uint16_t *copied);

/*****Jump*****/

/**
 * \brief Jumps by a value specified by the user.  In other words this works
 *        like a seek, although the data pointer can only be moved forward.
 *
 * \param ctx Pointer to the streaming parser context.
 * \param jump No of bytes to jump.
 * \param copied Pointer to var that would be updated by the API to indicate
 *               the no of bytes jumped.
 *
 * \retval STREAMING_PARSER_ROK, if the value specified by the user has been
 *         jumped by the API.
 *         STREAMING_PARSER_RDATA, if there wasn't sufficient data to jump.
 *         In such a case the API would jump over the existing data available,
 *         and the user can read the amount of bytes jumped through the
 *         "jumped" argument supplied.
 */
int StreamingParserJump(void *ctx, uint16_t jump, uint16_t *jumped);

void StreamingParserRegisterUnittets(void);

#endif /* __UTIL_STREAMING_PARSER_H__ */
