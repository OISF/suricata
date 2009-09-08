/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __UTIL_BYTE_H__
#define __UTIL_BYTE_H__

#include <stdint.h>

#define BYTE_BIG_ENDIAN      0
#define BYTE_LITTLE_ENDIAN   1

/**
 * Extract bytes from a byte string and convert to a unint64_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return 0 On success
 */
int ByteExtractUint64(uint64_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract bytes from a byte string and convert to a unint32_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractUint32(uint32_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract bytes from a byte string and convert to a unint16_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractUint16(uint16_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract unsigned integer value from a string.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractString(uint64_t *res, int base, uint16_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint64_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param len Number of bytes to extract (23 max)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringUint64(uint64_t *res, int base, uint16_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint32_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringUint32(uint32_t *res, int base, uint16_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint16_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringUint16(uint16_t *res, int base, uint16_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint8_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringUint8(uint8_t *res, int base, uint16_t len, const char *str);

/**
 * Extract signed integer value from a string.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringSigned(int64_t *res, int base, uint16_t len, const char *str);

/**
 * Extract signed integer value from a string as uint64_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringInt64(int64_t *res, int base, uint16_t len, const char *str);

/**
 * Extract signed integer value from a string as uint32_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringInt32(int32_t *res, int base, uint16_t len, const char *str);

/**
 * Extract signed integer value from a string as uint16_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringInt16(int16_t *res, int base, uint16_t len, const char *str);

/**
 * Extract signed integer value from a string as uint8_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return 0 On success
 */
inline int ByteExtractStringInt8(int8_t *res, int base, uint16_t len, const char *str);

#ifdef UNITTESTS
void ByteRegisterTests(void);
#endif /* UNITTESTS */


#endif /* __UTIL_BYTE_H__ */

