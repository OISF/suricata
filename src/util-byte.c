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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Byte utility functions
 */

#include "suricata-common.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"

/** \brief Turn byte array into string.
 *
 *  All non-printables are copied over, except for '\0', which is
 *  turned into literal \0 in the string.
 *
 *  \param bytes byte array
 *  \param nbytes number of bytes
 *  \return string nul-terminated string or NULL on error
 */
char *BytesToString(const uint8_t *bytes, size_t nbytes)
{
    size_t n = nbytes + 1;
    size_t nulls = 0;

    size_t u;
    for (u = 0; u < nbytes; u++) {
        if (bytes[u] == '\0')
            nulls++;
    }
    n += nulls;

    char *string = SCCalloc(1, n);
    if (string == NULL)
        return NULL;

    if (nulls == 0) {
        /* no nulls */
        memcpy(string, bytes, nbytes);
    } else {
        /* nulls present */
        char *dst = string;
        for (u = 0; u < nbytes; u++) {
            if (bytes[u] == '\0') {
                *dst++ = '\\';
                *dst++ = '0';
            } else {
                *dst++ = bytes[u];
            }
        }
    }
    return string;
}

int ByteExtractUint64(uint64_t *res, int e, uint16_t len, const uint8_t *bytes)
{
    uint64_t i64;
    int ret;

    /* Uint64 is limited to 8 bytes */
    if (len > 8) {
        /** \todo Need standard return values */
        return -1;
    }

    ret = ByteExtract(&i64, e, len, bytes);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint64_t)i64;

    return ret;
}

int ByteExtractUint32(uint32_t *res, int e, uint16_t len, const uint8_t *bytes)
{
    uint64_t i64;
    int ret;

    /* Uint32 is limited to 4 bytes */
    if (len > 4) {
        /** \todo Need standard return values */
        return -1;
    }

    ret = ByteExtract(&i64, e, len, bytes);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint32_t)i64;

    return ret;
}

int ByteExtractUint16(uint16_t *res, int e, uint16_t len, const uint8_t *bytes)
{
    uint64_t i64;
    int ret;

    /* Uint16 is limited to 2 bytes */
    if (len > 2) {
        /** \todo Need standard return values */
        return -1;
    }

    ret = ByteExtract(&i64, e, len, bytes);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint16_t)i64;

    return ret;
}

int ByteExtractString(uint64_t *res, int base, uint16_t len, const char *str)
{
    const char *ptr = str;
    char *endptr = NULL;

    /* 23 - This is the largest string (octal, with a zero prefix) that
     *      will not overflow uint64_t.  The only way this length
     *      could be over 23 and still not overflow is if it were zero
     *      prefixed and we only support 1 byte of zero prefix for octal.
     *
     * "01777777777777777777777" = 0xffffffffffffffff
     */
    char strbuf[24];

    if (len > 23) {
        SCLogError(SC_ERR_ARG_LEN_LONG, "len too large (23 max)");
        return -1;
    }

    if (len) {
        /* Extract out the string so it can be null terminated */
        memcpy(strbuf, str, len);
        strbuf[len] = '\0';
        ptr = strbuf;
    }

    errno = 0;
    *res = strtoull(ptr, &endptr, base);

    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        return -1;
        /* If there is no numeric value in the given string then strtoull(), makes
        endptr equals to ptr and return 0 as result */
    } else if (endptr == ptr && *res == 0) {
        SCLogDebug("No numeric value");
        return -1;
    } else if (endptr == ptr) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        return -1;
    }
    /* This will interfere with some rules that do not know the length
     * in advance and instead are just using the max.
     */
#if 0
    else if (len && *endptr != '\0') {
        fprintf(stderr, "ByteExtractString: Extra characters following numeric value\n");
        return -1;
    }
#endif

    return (endptr - ptr);
}

int ByteExtractStringUint64(uint64_t *res, int base, uint16_t len, const char *str)
{
    return ByteExtractString(res, base, len, str);
}

int ByteExtractStringUint32(uint32_t *res, int base, uint16_t len, const char *str)
{
    uint64_t i64;
    int ret;

    ret = ByteExtractString(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint32_t)i64;

    if ((uint64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIu64 " > %" PRIuMAX ")", i64, (uintmax_t)UINT_MAX);
        return -1;
    }

    return ret;
}

int ByteExtractStringUint16(uint16_t *res, int base, uint16_t len, const char *str)
{
    uint64_t i64;
    int ret;

    ret = ByteExtractString(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint16_t)i64;

    if ((uint64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIu64 " > %" PRIuMAX ")", i64, (uintmax_t)USHRT_MAX);
        return -1;
    }

    return ret;
}

int ByteExtractStringUint8(uint8_t *res, int base, uint16_t len, const char *str)
{
    uint64_t i64;
    int ret;

    ret = ByteExtractString(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (uint8_t)i64;

    if ((uint64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIu64 " > %" PRIuMAX ")", i64, (uintmax_t)UCHAR_MAX);
        return -1;
    }

    return ret;
}

int ByteExtractStringSigned(int64_t *res, int base, uint16_t len, const char *str)
{
    const char *ptr = str;
    char *endptr;

    /* 23 - This is the largest string (octal, with a zero prefix) that
     *      will not overflow int64_t.  The only way this length
     *      could be over 23 and still not overflow is if it were zero
     *      prefixed and we only support 1 byte of zero prefix for octal.
     *
     * "-0777777777777777777777" = 0xffffffffffffffff
     */
    char strbuf[24];

    if (len > 23) {
        SCLogError(SC_ERR_ARG_LEN_LONG, "len too large (23 max)");
        return -1;
    }

    if (len) {
        /* Extract out the string so it can be null terminated */
        memcpy(strbuf, str, len);
        strbuf[len] = '\0';
        ptr = strbuf;
    }

    errno = 0;
    *res = strtoll(ptr, &endptr, base);

    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        return -1;
    } else if (endptr == str) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        return -1;
    }
    /* This will interfere with some rules that do not know the length
     * in advance and instead are just using the max.
     */
#if 0
    else if (len && *endptr != '\0') {
        fprintf(stderr, "ByteExtractStringSigned: Extra characters following numeric value\n");
        return -1;
    }
#endif

    //fprintf(stderr, "ByteExtractStringSigned: Extracted base %d: 0x%" PRIx64 "\n", base, *res);

    return (endptr - ptr);
}

int ByteExtractStringInt64(int64_t *res, int base, uint16_t len, const char *str)
{
    return ByteExtractStringSigned(res, base, len, str);
}

int ByteExtractStringInt32(int32_t *res, int base, uint16_t len, const char *str)
{
    int64_t i64;
    int ret;

    ret = ByteExtractStringSigned(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (int32_t)i64;

    if ((int64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIi64 " > %" PRIiMAX ")\n", i64, (intmax_t)INT_MAX);
        return -1;
    }

    return ret;
}

int ByteExtractStringInt16(int16_t *res, int base, uint16_t len, const char *str)
{
    int64_t i64;
    int ret;

    ret = ByteExtractStringSigned(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (int16_t)i64;

    if ((int64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIi64 " > %" PRIiMAX ")\n", i64, (intmax_t)SHRT_MAX);
        return -1;
    }

    return ret;
}

int ByteExtractStringInt8(int8_t *res, int base, uint16_t len, const char *str)
{
    int64_t i64;
    int ret;

    ret = ByteExtractStringSigned(&i64, base, len, str);
    if (ret <= 0) {
        return ret;
    }

    *res = (int8_t)i64;

    if ((int64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                   "(%" PRIi64 " > %" PRIiMAX ")\n", i64, (intmax_t)CHAR_MAX);
        return -1;
    }

    return ret;
}

/* UNITTESTS */
#ifdef UNITTESTS

static int ByteTest01 (void)
{
    uint16_t val = 0x0102;
    uint16_t i16 = 0xbfbf;
    uint8_t bytes[2] = { 0x02, 0x01 };
    int ret = ByteExtractUint16(&i16, BYTE_LITTLE_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 2) && (i16 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest02 (void)
{
    uint16_t val = 0x0102;
    uint16_t i16 = 0xbfbf;
    uint8_t bytes[2] = { 0x01, 0x02 };
    int ret = ByteExtractUint16(&i16, BYTE_BIG_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 2) && (i16 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest03 (void)
{
    uint32_t val = 0x01020304;
    uint32_t i32 = 0xbfbfbfbf;
    uint8_t bytes[4] = { 0x04, 0x03, 0x02, 0x01 };
    int ret = ByteExtractUint32(&i32, BYTE_LITTLE_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 4) && (i32 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest04 (void)
{
    uint32_t val = 0x01020304;
    uint32_t i32 = 0xbfbfbfbf;
    uint8_t bytes[4] = { 0x01, 0x02, 0x03, 0x04 };
    int ret = ByteExtractUint32(&i32, BYTE_BIG_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 4) && (i32 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest05 (void)
{
    uint64_t val = 0x0102030405060708ULL;
    uint64_t i64 = 0xbfbfbfbfbfbfbfbfULL;
    uint8_t bytes[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    int ret = ByteExtractUint64(&i64, BYTE_LITTLE_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 8) && (i64 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest06 (void)
{
    uint64_t val = 0x0102030405060708ULL;
    uint64_t i64 = 0xbfbfbfbfbfbfbfbfULL;
    uint8_t bytes[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    int ret = ByteExtractUint64(&i64, BYTE_BIG_ENDIAN, sizeof(bytes), bytes);

    if ((ret == 8) && (i64 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest07 (void)
{
    const char *str = "1234567890";
    uint64_t val = 1234567890;
    uint64_t i64 = 0xbfbfbfbfbfbfbfbfULL;
    int ret = ByteExtractStringUint64(&i64, 10, strlen(str), str);

    if ((ret == 10) && (i64 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest08 (void)
{
    const char *str = "1234567890";
    uint32_t val = 1234567890;
    uint32_t i32 = 0xbfbfbfbf;
    int ret = ByteExtractStringUint32(&i32, 10, strlen(str), str);

    if ((ret == 10) && (i32 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest09 (void)
{
    const char *str = "12345";
    uint16_t val = 12345;
    uint16_t i16 = 0xbfbf;
    int ret = ByteExtractStringUint16(&i16, 10, strlen(str), str);

    if ((ret == 5) && (i16 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest10 (void)
{
    const char *str = "123";
    uint8_t val = 123;
    uint8_t i8 = 0xbf;
    int ret = ByteExtractStringUint8(&i8, 10, strlen(str), str);

    if ((ret == 3) && (i8 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest11 (void)
{
    const char *str = "-1234567890";
    int64_t val = -1234567890;
    int64_t i64 = 0xbfbfbfbfbfbfbfbfULL;
    int ret = ByteExtractStringInt64(&i64, 10, strlen(str), str);

    if ((ret == 11) && (i64 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest12 (void)
{
    const char *str = "-1234567890";
    int32_t val = -1234567890;
    int32_t i32 = 0xbfbfbfbf;
    int ret = ByteExtractStringInt32(&i32, 10, strlen(str), str);

    if ((ret == 11) && (i32 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest13 (void)
{
    const char *str = "-12345";
    int16_t val = -12345;
    int16_t i16 = 0xbfbf;
    int ret = ByteExtractStringInt16(&i16, 10, strlen(str), str);

    if ((ret == 6) && (i16 == val)) {
        return 1;
    }

    return 0;
}

static int ByteTest14 (void)
{
    const char *str = "-123";
    int8_t val = -123;
    int8_t i8 = 0xbf;
    int ret = ByteExtractStringInt8(&i8, 10, strlen(str), str);

    if ((ret == 4) && (i8 == val)) {
        return 1;
    }

    return 0;
}

/** \test max u32 value */
static int ByteTest15 (void)
{
    const char *str = "4294967295";
    uint32_t val = 4294967295UL;
    uint32_t u32 = 0xffffffff;

    int ret = ByteExtractStringUint32(&u32, 10, strlen(str), str);
    if ((ret == 10) && (u32 == val)) {
        return 1;
    }

    return 0;
}

/** \test max u32 value + 1 */
static int ByteTest16 (void)
{
    const char *str = "4294967296";
    uint32_t u32 = 0;

    int ret = ByteExtractStringUint32(&u32, 10, strlen(str), str);
    if (ret != 0) {
        return 1;
    }

    return 0;
}

void ByteRegisterTests(void)
{
    UtRegisterTest("ByteTest01", ByteTest01);
    UtRegisterTest("ByteTest02", ByteTest02);
    UtRegisterTest("ByteTest03", ByteTest03);
    UtRegisterTest("ByteTest04", ByteTest04);
    UtRegisterTest("ByteTest05", ByteTest05);
    UtRegisterTest("ByteTest06", ByteTest06);
    UtRegisterTest("ByteTest07", ByteTest07);
    UtRegisterTest("ByteTest08", ByteTest08);
    UtRegisterTest("ByteTest09", ByteTest09);
    UtRegisterTest("ByteTest10", ByteTest10);
    UtRegisterTest("ByteTest11", ByteTest11);
    UtRegisterTest("ByteTest12", ByteTest12);
    UtRegisterTest("ByteTest13", ByteTest13);
    UtRegisterTest("ByteTest14", ByteTest14);
    UtRegisterTest("ByteTest15", ByteTest15);
    UtRegisterTest("ByteTest16", ByteTest16);
}
#endif /* UNITTESTS */

