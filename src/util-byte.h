/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __UTIL_BYTE_H__
#define __UTIL_BYTE_H__

#include <stdint.h>

#define BYTE_BIG_ENDIAN      0
#define BYTE_LITTLE_ENDIAN   1

/** Wrappers for OS dependent byte swapping functions */
#ifdef OS_FREEBSD
#include <sys/endian.h>
#define SCByteSwap16(x) bswap16(x)
#define SCByteSwap32(x) bswap32(x)
#define SCByteSwap64(x) bswap64(x)
#elif defined __OpenBSD__
#include <sys/types.h>
#define SCByteSwap16(x) swap16(x)
#define SCByteSwap32(x) swap32(x)
#define SCByteSwap64(x) swap64(x)
#elif OS_DARWIN
#include <libkern/OSByteOrder.h>
#define SCByteSwap16(x) OSSwapInt16(x)
#define SCByteSwap32(x) OSSwapInt32(x)
#define SCByteSwap64(x) OSSwapInt64(x)
#elif defined(__WIN32) || defined(_WIN32) || defined(sun)
/* Quick & dirty solution, nothing seems to exist for this in Win32 API */
#define SCByteSwap16(x)                         \
	((((x) & 0xff00) >> 8)                      \
	| (((x) & 0x00ff) << 8))
#define SCByteSwap32(x)                         \
	((((x) & 0xff000000) >> 24)                 \
	| (((x) & 0x00ff0000) >> 8)                 \
	| (((x) & 0x0000ff00) << 8)                 \
	| (((x) & 0x000000ff) << 24))
#define SCByteSwap64(x)                         \
	((((x) & 0xff00000000000000ull) >> 56)      \
	| (((x) & 0x00ff000000000000ull) >> 40)     \
	| (((x) & 0x0000ff0000000000ull) >> 24)     \
	| (((x) & 0x000000ff00000000ull) >> 8)      \
	| (((x) & 0x00000000ff000000ull) << 8)      \
	| (((x) & 0x0000000000ff0000ull) << 24)     \
	| (((x) & 0x000000000000ff00ull) << 40)     \
	| (((x) & 0x00000000000000ffull) << 56))
#else
#include <byteswap.h>
#define SCByteSwap16(x) bswap_16(x)
#define SCByteSwap32(x) bswap_32(x)
#define SCByteSwap64(x) bswap_64(x)
#endif /* OS_FREEBSD */

/** \brief Turn byte array into string.
 *
 *  All non-printables are copied over, except for '\0', which is
 *  turned into literal \0 in the string.
 *
 *  \param bytes byte array
 *  \param nbytes number of bytes
 *  \return string nul-terminated string or NULL on error
 */
char *BytesToString(const uint8_t *bytes, size_t nbytes);
void BytesToStringBuffer(const uint8_t *bytes, size_t nbytes, char *outstr, size_t outlen);

/**
 * Extract bytes from a byte string and convert to a unint64_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractUint64(uint64_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract bytes from a byte string and convert to a uint32_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractUint32(uint32_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract bytes from a byte string and convert to a unint16_t.
 *
 * \param res Stores result
 * \param e Endianness (BYTE_BIG_ENDIAN or BYTE_LITTLE_ENDIAN)
 * \param len Number of bytes to extract (8 max)
 * \param bytes Data to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractUint16(uint16_t *res, int e, uint16_t len, const uint8_t *bytes);

/**
 * Extract unsigned integer value from a string.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 * \param bool Enable strict check for parsers
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractString(uint64_t *res, int base, size_t len, const char *str, bool strict);

/**
 * Extract unsigned integer value from a string as uint64_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringUint64(uint64_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint32_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringUint32(uint32_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint16_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringUint16(uint16_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint8_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringUint8(uint8_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 * \param bool Enable strict check for parsers
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringSigned(int64_t *res, int base, size_t len, const char *str, bool strict);

/**
 * Extract signed integer value from a string as uint64_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringInt64(int64_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as uint32_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringInt32(int32_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as uint16_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringInt16(int16_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as uint8_t.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int ByteExtractStringInt8(int8_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint64_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseUint64(uint64_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint32_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseUint32(uint32_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint16_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseUint16(uint16_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint8_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseUint8(uint8_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as int64_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseInt64(int64_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as int32_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseInt32(int32_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as int16_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseInt16(int16_t *res, int base, size_t len, const char *str);

/**
 * Extract signed integer value from a string as int8_t strictly.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int StringParseInt8(int8_t *res, int base, size_t len, const char *str);

/**
 * Extract unsigned integer value from a string as uint64_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseU64RangeCheck(
        uint64_t *res, int base, size_t len, const char *str, uint64_t min, uint64_t max);

/**
 * Extract unsigned integer value from a string as uint32_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseU32RangeCheck(
        uint32_t *res, int base, size_t len, const char *str, uint32_t min, uint32_t max);

/**
 * Extract unsigned integer value from a string as uint16_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseU16RangeCheck(
        uint16_t *res, int base, size_t len, const char *str, uint16_t min, uint16_t max);

/**
 * Extract unsigned integer value from a string as uint8_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseU8RangeCheck(
        uint8_t *res, int base, size_t len, const char *str, uint8_t min, uint8_t max);

/**
 * Extract signed integer value from a string as int64_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseI64RangeCheck(
        int64_t *res, int base, size_t len, const char *str, int64_t min, int64_t max);

/**
 * Extract signed integer value from a string as int32_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseI32RangeCheck(
        int32_t *res, int base, size_t len, const char *str, int32_t min, int32_t max);

/**
 * Extract signed integer value from a string as int16_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseI16RangeCheck(
        int16_t *res, int base, size_t len, const char *str, int16_t min, int16_t max);

/**
 * Extract signed integer value from a string as int8_t strictly within the range.
 *
 * \param res Stores result
 * \param base Base of the number to extract
 * \param len Number of bytes to extract (23 max or 0 for unbounded)
 * \param str String to extract from
 *
 * \return n Number of bytes extracted on success
 * \return -1 On error
 */
int WARN_UNUSED StringParseI8RangeCheck(
        int8_t *res, int base, size_t len, const char *str, int8_t min, int8_t max);

#ifdef UNITTESTS
void ByteRegisterTests(void);
#endif /* UNITTESTS */

/** ------ Inline functions ----- */
static inline int ByteExtract(uint64_t *res, int e, uint16_t len, const uint8_t *bytes)
{
    if ((e != BYTE_BIG_ENDIAN) && (e != BYTE_LITTLE_ENDIAN)) {
        /** \todo Need standard return values */
        return -1;
    }

    *res = 0;

    /* Go through each byte and merge it into the result in the correct order */
    /** \todo Probably a more efficient way to do this. */
    for (int i = 0; i < len; i++) {
        uint64_t b;
        if (e == BYTE_LITTLE_ENDIAN) {
            b = bytes[i];
        }
        else {
            b = bytes[len - i - 1];
        }

        *res |= (b << ((i & 7) << 3));
    }

    return len;
}

#endif /* __UTIL_BYTE_H__ */
