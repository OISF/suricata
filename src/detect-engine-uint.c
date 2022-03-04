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
#define PARSE_REGEX "^\\s*([0-9]*)?\\s*([!<>=-]+)?\\s*([0-9]+)?\\s*$"

static DetectParseRegex uint_pcre;


int DetectU32Match(const uint32_t parg, const DetectU32Data *du32)
{
    switch (du32->mode) {
        case DETECT_UINT_EQ:
            if (parg == du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_NE:
            if (parg != du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LTE:
            if (parg <= du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du32->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GTE:
            if (parg >= du32->arg1) {
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

static int DetectU32Validate(DetectU32Data *du32)
{
    switch (du32->mode) {
        case DETECT_UINT_LT:
            if (du32->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_LTE:
            if (du32->arg1 == UINT32_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_GTE:
            if (du32->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_GT:
            if (du32->arg1 == UINT32_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_RA:
            if (du32->arg1 >= du32->arg2) {
                return 1;
            }
            // we need at least one value that can match parg > du32->arg1 && parg < du32->arg2
            if (du32->arg1 + 1 >= du32->arg2) {
                return 1;
            }
            break;
        default:
            break;
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
    size_t pcre2len;

    ret = DetectParsePcreExec(&uint_pcre, u32str, 0, 0);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    pcre2len = sizeof(arg1);
    res = pcre2_substring_copy_bynumber(uint_pcre.match, 1, (PCRE2_UCHAR8 *)arg1, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        pcre2len = sizeof(arg2);
        res = pcre2_substring_copy_bynumber(uint_pcre.match, 2, (PCRE2_UCHAR8 *)arg2, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return NULL;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            pcre2len = sizeof(arg3);
            res = pcre2_substring_copy_bynumber(
                    uint_pcre.match, 3, (PCRE2_UCHAR8 *)arg3, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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
            case '!':
                if (strlen(arg2) == 1) {
                    if (strlen(arg3) == 0)
                        return NULL;

                    if (ByteExtractStringUint32(&u32da.arg1, 10, strlen(arg3), arg3) < 0) {
                        SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint32 failed");
                        return NULL;
                    }

                    SCLogDebug("u32 is %" PRIu32 "", u32da.arg1);
                    if (strlen(arg1) > 0)
                        return NULL;

                    if (arg2[0] == '<') {
                        u32da.mode = DETECT_UINT_LT;
                    } else if (arg2[0] == '>') {
                        u32da.mode = DETECT_UINT_GT;
                    } else { // if (arg2[0] == '!')
                        u32da.mode = DETECT_UINT_NE;
                    }
                    break;
                } else if (strlen(arg2) == 2) {
                    if (arg2[0] == '<' && arg2[1] == '=') {
                        u32da.mode = DETECT_UINT_LTE;
                        break;
                    } else if (arg2[0] == '>' || arg2[1] == '=') {
                        u32da.mode = DETECT_UINT_GTE;
                        break;
                    } else if (arg2[0] != '<' || arg2[1] != '>') {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
                // fall through
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
    if (DetectU32Validate(&u32da)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Impossible value for uint32 condition : %s", u32str);
        return NULL;
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
        case DETECT_UINT_NE:
            if (parg != du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LTE:
            if (parg <= du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du8->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GTE:
            if (parg >= du8->arg1) {
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

static int DetectU8Validate(DetectU8Data *du8)
{
    switch (du8->mode) {
        case DETECT_UINT_LT:
            if (du8->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_LTE:
            if (du8->arg1 == UINT8_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_GTE:
            if (du8->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_GT:
            if (du8->arg1 == UINT8_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_RA:
            if (du8->arg1 >= du8->arg2) {
                return 1;
            }
            // we need at least one value that can match parg > du8->arg1 && parg < du8->arg2
            if (du8->arg1 + 1 >= du8->arg2) {
                return 1;
            }
            break;
        default:
            break;
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
    size_t pcre2len;

    ret = DetectParsePcreExec(&uint_pcre, u8str, 0, 0);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    pcre2len = sizeof(arg1);
    res = pcre2_substring_copy_bynumber(uint_pcre.match, 1, (PCRE2_UCHAR8 *)arg1, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        pcre2len = sizeof(arg2);
        res = pcre2_substring_copy_bynumber(uint_pcre.match, 2, (PCRE2_UCHAR8 *)arg2, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return NULL;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            pcre2len = sizeof(arg3);
            res = pcre2_substring_copy_bynumber(
                    uint_pcre.match, 3, (PCRE2_UCHAR8 *)arg3, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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
            case '!':
                if (strlen(arg2) == 1) {
                    if (StringParseUint8(&u8da.arg1, 10, strlen(arg3), arg3) < 0) {
                        SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint8 failed");
                        return NULL;
                    }

                    SCLogDebug("u8 is %" PRIu8 "", u8da.arg1);
                    if (strlen(arg1) > 0)
                        return NULL;

                    if (arg2[0] == '<') {
                        u8da.mode = DETECT_UINT_LT;
                    } else if (arg2[0] == '>') {
                        u8da.mode = DETECT_UINT_GT;
                    } else { // if (arg2[0] == '!')
                        u8da.mode = DETECT_UINT_NE;
                    }
                    break;
                } else if (strlen(arg2) == 2) {
                    if (arg2[0] == '<' && arg2[1] == '=') {
                        u8da.mode = DETECT_UINT_LTE;
                        break;
                    } else if (arg2[0] == '>' || arg2[1] == '=') {
                        u8da.mode = DETECT_UINT_GTE;
                        break;
                    } else if (arg2[0] != '<' || arg2[1] != '>') {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
                // fall through
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
    if (DetectU8Validate(&u8da)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Impossible value for uint8 condition : %s", u8str);
        return NULL;
    }
    u8d = SCCalloc(1, sizeof (DetectU8Data));
    if (unlikely(u8d == NULL))
        return NULL;
    u8d->arg1 = u8da.arg1;
    u8d->arg2 = u8da.arg2;
    u8d->mode = u8da.mode;

    return u8d;
}

// same as u32 but with u16
int DetectU16Match(const uint16_t parg, const DetectU16Data *du16)
{
    switch (du16->mode) {
        case DETECT_UINT_EQ:
            if (parg == du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_NE:
            if (parg != du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LT:
            if (parg < du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_LTE:
            if (parg <= du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GT:
            if (parg > du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_GTE:
            if (parg >= du16->arg1) {
                return 1;
            }
            return 0;
        case DETECT_UINT_RA:
            if (parg > du16->arg1 && parg < du16->arg2) {
                return 1;
            }
            return 0;
        default:
            BUG_ON("unknown mode");
    }
    return 0;
}

static int DetectU16Validate(DetectU16Data *du16)
{
    switch (du16->mode) {
        case DETECT_UINT_LT:
            if (du16->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_LTE:
            if (du16->arg1 == UINT16_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_GTE:
            if (du16->arg1 == 0) {
                return 1;
            }
            break;
        case DETECT_UINT_GT:
            if (du16->arg1 == UINT16_MAX) {
                return 1;
            }
            break;
        case DETECT_UINT_RA:
            if (du16->arg1 >= du16->arg2) {
                return 1;
            }
            // we need at least one value that can match parg > du16->arg1 && parg < du16->arg2
            if (du16->arg1 + 1 >= du16->arg2) {
                return 1;
            }
            break;
        default:
            break;
    }
    return 0;
}

/**
 * \brief This function is used to parse u16 options passed via some u16 keyword
 *
 * \param u16str Pointer to the user provided u16 options
 *
 * \retval DetectU16Data pointer to DetectU16Data on success
 * \retval NULL on failure
 */

DetectU16Data *DetectU16Parse(const char *u16str)
{
    /* We initialize these to please static checkers, these values will
       either be updated or not used later on */
    DetectU16Data u16da = { 0, 0, 0 };
    DetectU16Data *u16d = NULL;
    char arg1[16] = "";
    char arg2[16] = "";
    char arg3[16] = "";

    int ret = 0, res = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&uint_pcre, u16str, 0, 0);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    pcre2len = sizeof(arg1);
    res = pcre2_substring_copy_bynumber(uint_pcre.match, 1, (PCRE2_UCHAR8 *)arg1, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        pcre2len = sizeof(arg2);
        res = pcre2_substring_copy_bynumber(uint_pcre.match, 2, (PCRE2_UCHAR8 *)arg2, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return NULL;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            pcre2len = sizeof(arg3);
            res = pcre2_substring_copy_bynumber(
                    uint_pcre.match, 3, (PCRE2_UCHAR8 *)arg3, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                return NULL;
            }
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    if (strlen(arg2) > 0) {
        /*set the values*/
        switch (arg2[0]) {
            case '<':
            case '>':
            case '!':
                if (strlen(arg2) == 1) {
                    if (StringParseUint16(&u16da.arg1, 10, strlen(arg3), arg3) < 0) {
                        SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint16 failed");
                        return NULL;
                    }

                    SCLogDebug("u16 is %" PRIu16 "", u16da.arg1);
                    if (strlen(arg1) > 0)
                        return NULL;

                    if (arg2[0] == '<') {
                        u16da.mode = DETECT_UINT_LT;
                    } else if (arg2[0] == '>') {
                        u16da.mode = DETECT_UINT_GT;
                    } else { // if (arg2[0] == '!')
                        u16da.mode = DETECT_UINT_NE;
                    }
                    break;
                } else if (strlen(arg2) == 2) {
                    if (arg2[0] == '<' && arg2[1] == '=') {
                        u16da.mode = DETECT_UINT_LTE;
                        break;
                    } else if (arg2[0] == '>' || arg2[1] == '=') {
                        u16da.mode = DETECT_UINT_GTE;
                        break;
                    } else if (arg2[0] != '<' || arg2[1] != '>') {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
                // fall through
            case '-':
                u16da.mode = DETECT_UINT_RA;
                if (StringParseUint16(&u16da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint16 failed");
                    return NULL;
                }
                if (StringParseUint16(&u16da.arg2, 10, strlen(arg3), arg3) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint16 failed");
                    return NULL;
                }

                SCLogDebug("u16 is %" PRIu16 " to %" PRIu16 "", u16da.arg1, u16da.arg2);
                if (u16da.arg1 >= u16da.arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid u16 range. ");
                    return NULL;
                }
                break;
            default:
                u16da.mode = DETECT_UINT_EQ;

                if (strlen(arg2) > 0 || strlen(arg3) > 0)
                    return NULL;

                if (StringParseUint16(&u16da.arg1, 10, strlen(arg1), arg1) < 0) {
                    SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint16 failed");
                    return NULL;
                }
        }
    } else {
        u16da.mode = DETECT_UINT_EQ;

        if (strlen(arg3) > 0)
            return NULL;

        if (StringParseUint16(&u16da.arg1, 10, strlen(arg1), arg1) < 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED, "ByteExtractStringUint16 failed");
            return NULL;
        }
    }
    if (DetectU16Validate(&u16da)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Impossible value for uint16 condition : %s", u16str);
        return NULL;
    }
    u16d = SCCalloc(1, sizeof(DetectU16Data));
    if (unlikely(u16d == NULL))
        return NULL;
    u16d->arg1 = u16da.arg1;
    u16d->arg2 = u16da.arg2;
    u16d->mode = u16da.mode;

    return u16d;
}

void PrefilterPacketU16Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectU16Data *a = smctx;
    v->u8[0] = a->mode;
    v->u16[1] = a->arg1;
    v->u16[2] = a->arg2;
}

bool PrefilterPacketU16Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectU16Data *a = smctx;
    if (v.u8[0] == a->mode && v.u16[1] == a->arg1 && v.u16[2] == a->arg2)
        return true;
    return false;
}
