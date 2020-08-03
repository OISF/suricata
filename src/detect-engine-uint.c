/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 */

#include "suricata-common.h"

#include "util-byte.h"
#include "detect-parse.h"
#include "detect-engine-uint.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static DetectParseRegex uint_pcre;


int DetectU32Match(const uint32_t parg, const DetectU32Data *du32)
{
    switch (du32->mode) {
        case DETECT_UINT_EQ:
            if (parg == du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_RA:
            if (parg > du32->arg1 && parg < du32->arg2) {
                return 1;
            }
            return 0;
        default:
            BUG_ON("unknown mode");
    }
    return 0;
}


/**
 * \brief This function is used to parse u32 options passed via some u32 keyword
 *
 * \param u32str Pointer to the user provided u32 options
 *
 * \retval DetectU32Data pointer to DetectU32Data on success
 * \retval NULL on failure
 */

DetectU32Data *DetectU32Parse (const char *u32str)
{
    /* We initialize these to please static checkers, these values will
       either be updated or not used later on */
    DetectU32Data u32da = {0, 0, 0};
    DetectU32Data *u32d = NULL;
    char arg1[16] = "";
    char arg2[16] = "";
    char arg3[16] = "";

    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&uint_pcre, u32str, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
            return NULL;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_copy_substring((char *) u32str, ov, MAX_SUBSTRINGS, 3, arg3, sizeof(arg3));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                return NULL;
            }
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    if (strlen(arg2) > 0) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
            case '>':
                if (strlen(arg3) == 0)
                    return NULL;

                if (ByteExtractStringUint32(&u32da.arg1, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    return NULL;
                }

                SCLogDebug("u32 is %"PRIu32"",u32da.arg1);
                if (strlen(arg1) > 0)
                    return NULL;

                if (arg2[0] == '<') {
                    u32da.mode = DETECT_UINT_LT;
                } else { // arg2[0] == '>'
                    u32da.mode = DETECT_UINT_GT;
                }
                break;
            case '-':
                if (strlen(arg1)== 0)
                    return NULL;
                if (strlen(arg3)== 0)
                    return NULL;

                u32da.mode = DETECT_UINT_RA;
                if (ByteExtractStringUint32(&u32da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    return NULL;
                }
                if (ByteExtractStringUint32(&u32da.arg2, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    return NULL;
                }

                SCLogDebug("u32 is %"PRIu32" to %"PRIu32"", u32da.arg1, u32da.arg2);
                if (u32da.arg1 >= u32da.arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid u32 range. ");
                    return NULL;
                }
                break;
            default:
                u32da.mode = DETECT_UINT_EQ;

                if (strlen(arg2) > 0 ||
                    strlen(arg3) > 0 ||
                    strlen(arg1) == 0)
                    return NULL;

                if (ByteExtractStringUint32(&u32da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                    return NULL;
                }
        }
    } else {
        u32da.mode = DETECT_UINT_EQ;

        if (strlen(arg3) > 0 ||
            strlen(arg1) == 0)
            return NULL;

        if (ByteExtractStringUint32(&u32da.arg1, 10, strlen(arg1), arg1) < 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
            return NULL;
        }
    }
    u32d = SCCalloc(1, sizeof (DetectU32Data));
    if (unlikely(u32d == NULL))
        return NULL;
    u32d->arg1 = u32da.arg1;
    u32d->arg2 = u32da.arg2;
    u32d->mode = u32da.mode;

    return u32d;
}

void
PrefilterPacketU32Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectU32Data *a = smctx;
    v->u8[0] = a->mode;
    v->u32[1] = a->arg1;
    v->u32[2] = a->arg2;
}

bool
PrefilterPacketU32Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectU32Data *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u32[1] == a->arg1 &&
        v.u32[2] == a->arg2)
        return true;
    return false;
}

static bool g_detect_uint_registered = false;

void DetectUintRegister(void)
{
    if (g_detect_uint_registered == false) {
        // register only once
        DetectSetupParseRegexes(PARSE_REGEX, &uint_pcre);
        g_detect_uint_registered = true;
    }
}

//same as u32 but with u8
int DetectU8Match(const uint8_t parg, const DetectU8Data *du8)
{
    switch (du8->mode) {
        case DETECT_UINT_EQ:
            if (parg == du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_RA:
            if (parg > du8->arg1 && parg < du8->arg2) {
                return 1;
            }
            return 0;
        default:
            BUG_ON("unknown mode");
    }
    return 0;
}

/**
 * \brief This function is used to parse u8 options passed via some u8 keyword
 *
 * \param u8str Pointer to the user provided u8 options
 *
 * \retval DetectU8Data pointer to DetectU8Data on success
 * \retval NULL on failure
 */

DetectU8Data *DetectU8Parse (const char *u8str)
{
    /* We initialize these to please static checkers, these values will
       either be updated or not used later on */
    DetectU8Data u8da = {0, 0, 0};
    DetectU8Data *u8d = NULL;
    char arg1[16] = "";
    char arg2[16] = "";
    char arg3[16] = "";

    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&uint_pcre, u8str, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    res = pcre_copy_substring((char *) u8str, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) u8str, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
            return NULL;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_copy_substring((char *) u8str, ov, MAX_SUBSTRINGS, 3, arg3, sizeof(arg3));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                return NULL;
            }
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    if (strlen(arg2) > 0) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
            case '>':
                if (StringParseUint8(&u8da.arg1, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
                    return NULL;
                }

                SCLogDebug("u8 is %"PRIu8"",u8da.arg1);
                if (strlen(arg1) > 0)
                    return NULL;

                if (arg2[0] == '<') {
                    u8da.mode = DETECT_UINT_LT;
                } else { // arg2[0] == '>'
                    u8da.mode = DETECT_UINT_GT;
                }
                break;
            case '-':
                u8da.mode = DETECT_UINT_RA;
                if (StringParseUint8(&u8da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
                    return NULL;
                }
                if (StringParseUint8(&u8da.arg2, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
                    return NULL;
                }

                SCLogDebug("u8 is %"PRIu8" to %"PRIu8"", u8da.arg1, u8da.arg2);
                if (u8da.arg1 >= u8da.arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid u8 range. ");
                    return NULL;
                }
                break;
            default:
                u8da.mode = DETECT_UINT_EQ;

                if (strlen(arg2) > 0 ||
                    strlen(arg3) > 0)
                    return NULL;

                if (StringParseUint8(&u8da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
                    return NULL;
                }
        }
    } else {
        u8da.mode = DETECT_UINT_EQ;

        if (strlen(arg3) > 0)
            return NULL;

        if (StringParseUint8(&u8da.arg1, 10, strlen(arg1), arg1) < 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
            return NULL;
        }
    }
    u8d = SCCalloc(1, sizeof (DetectU8Data));
    if (unlikely(u8d == NULL))
        return NULL;
    u8d->arg1 = u8da.arg1;
    u8d->arg2 = u8da.arg2;
    u8d->mode = u8da.mode;

    return u8d;
}
