/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Mahmoud Maatuq <mahmoudmatook.mm@gmail.com>
 *
 */

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "rust-bindings.h"
#include "app-layer-imap.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

#define IMAP_DEFAULT_PORT  "143"
#define IMAP_MIN_FRAME_LEN 6

/**
 * detection patterns conforms to RFC 9051 https://datatracker.ietf.org/doc/html/rfc9051,
 * IMAP4rev2 and also compatible with IMAP4rev1
 *
 * All interactions transmitted by client and server are in the form of lines, that is, strings that
 * end with a CRLF. The protocol receiver of an IMAP4rev2 client or server is reading either a line
 * or a sequence of octets with a known count followed by a line.
 * */

static bool __IMAPCompareBytesToCmd(const uint8_t *input, const char *cmd, uint32_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (tolower(input[i]) != tolower(cmd[i])) {
            return false;
        }
    }
    return true;
}

static uint32_t __IMAPMailCount(const uint8_t *input, uint32_t input_len, uint32_t offset)
{
    uint32_t space_pos = 0;
    for (size_t i = offset; i < input_len; ++i) {
        if (input[i] == ' ') {
            space_pos = i;
            break;
        }

        // mail count is always numeric.
        if (!isdigit(input[i])) {
            return 0;
        }
    }

    if (space_pos == offset || space_pos == (input_len - 1)) {
        return 0;
    }
    return space_pos + 1;
}

static uint32_t IMAPTaggedCmd(const uint8_t *input, uint32_t input_len)
{
    uint32_t space_pos = 0;
    for (size_t i = 0; i < input_len; ++i) {
        if (input[i] == ' ') {
            space_pos = i;
            break;
        }

        // tag is always alphanumeric.
        if (!isalnum(input[i])) {
            return 0;
        }
    }
    if (space_pos == 0 || space_pos == (input_len - 1)) {
        return 0;
    }
    return space_pos + 1;
}

static inline uint32_t IMAPUntaggedCmd(const uint8_t *input, uint32_t input_len)
{
    if (input_len <= 2) {
        return 0;
    }

    if (input[0] == '*' && input[1] == ' ') {
        return 2;
    }

    return 0;
}

static bool IMAPCmd(const uint8_t *input, uint32_t input_len, uint32_t command_start)
{

    /*client commands any state
     * https://datatracker.ietf.org/doc/html/rfc9051#name-client-commands-any-state
     * CAPABILITY
     * NOOP
     * LOGOUT
     * */

    if ((command_start + 10) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "CAPABILITY", 10)) {
        return true;
    }

    if ((command_start + 8) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "NOOP", 4)) {
        return true;
    }

    if ((command_start + 4) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "LOGOUT", 6)) {
        return true;
    }

    /*client commands non-authenticated state
     * https://datatracker.ietf.org/doc/html/rfc9051#name-client-commands-not-authent
     * STARTTLS
     * AUTHENTICATE
     * LOGIN
     * */

    if ((command_start + 8) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "STARTTLS", 8)) {
        return true;
    }

    if ((command_start + 12) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "AUTHENTICATE", 12)) {
        return true;
    }

    if ((command_start + 5) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "LOGIN", 5)) {
        return true;
    }

    /*client commands authenticated state
     * https://datatracker.ietf.org/doc/html/rfc9051#name-client-commands-authenticated
     * ENABLE
     * SELECT
     * EXAMINE
     * CREATE
     * DELETE
     * RENAME
     * SUBSCRIBE
     * UNSUBSCRIBE
     * LIST
     * NAMESPACE
     * STATUS
     * APPEND
     * IDLE
     * */
    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "ENABLE", 6)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "SELECT", 6)) {
        return true;
    }

    if ((command_start + 7) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "EXAMINE", 7)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "CREATE", 6)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "DELETE", 6)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "RENAME", 6)) {
        return true;
    }

    if ((command_start + 9) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "SUBSCRIBE", 9)) {
        return true;
    }

    if ((command_start + 11) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "UNSUBSCRIBE", 11)) {
        return true;
    }

    if ((command_start + 4) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "LIST", 4)) {
        return true;
    }

    if ((command_start + 9) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "NAMESPACE", 9)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "STATUS", 6)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "APPEND", 6)) {
        return true;
    }

    if ((command_start + 4) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "IDLE", 4)) {
        return true;
    }

    /*client commands selected state
     * https://datatracker.ietf.org/doc/html/rfc9051#name-client-commands-selected-st
     * CLOSE
     * UNSELECT
     * EXPUNGE
     * SEARCH
     * FETCH
     * STORE
     * COPY
     * MOVE
     * UID
     * */

    if ((command_start + 5) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "CLOSE", 5)) {
        return true;
    }

    if ((command_start + 8) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "UNSELECT", 8)) {
        return true;
    }

    if ((command_start + 7) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "EXPUNGE", 7)) {
        return true;
    }

    if ((command_start + 6) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "SEARCH", 6)) {
        return true;
    }

    if ((command_start + 5) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "FETCH", 5)) {
        return true;
    }

    if ((command_start + 5) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "STORE", 5)) {
        return true;
    }

    if ((command_start + 4) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "COPY", 4)) {
        return true;
    }

    if ((command_start + 4) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "MOVE", 4)) {
        return true;
    }

    if ((command_start + 3) < input_len &&
            __IMAPCompareBytesToCmd(input + command_start, "UID", 3)) {
        return true;
    }
    return false;
}

static bool IMAPServerResponseGenericStatus(const uint8_t *input, uint32_t input_len)
{
    /*generic status
     * https://datatracker.ietf.org/doc/html/rfc9051#name-generic-status
     * OK
     * NO
     * BAD
     * PREAUTH
     * BYE
     *  OK, NO, and BAD can be tagged or untagged. PREAUTH and BYE are always untagged.
     * */

    uint32_t command_start = 0;
    if ((command_start = IMAPUntaggedCmd(input, input_len))) {
        if ((command_start + 7) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "PREAUTH", 7)) {
            return true;
        }

        if ((command_start + 3) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "BYE", 3)) {
            return true;
        }
    }

    if ((command_start = IMAPUntaggedCmd(input, input_len)) ||
            (command_start = IMAPTaggedCmd(input, input_len))) {

        if ((command_start + 2) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "OK", 2)) {
            return true;
        }

        if ((command_start + 2) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "NO", 2)) {
            return true;
        }

        if ((command_start + 3) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "BAD", 3)) {
            return true;
        }
    }

    return false;
}

static bool IMAPServerResponseStatus(const uint8_t *input, uint32_t input_len)
{
    /*server status
     * https://datatracker.ietf.org/doc/html/rfc9051#name-server-status
     * ENABLED
     * CAPABILITY
     * These responses are always untagged.
     * */
    uint32_t command_start = 0;
    if ((command_start = IMAPUntaggedCmd(input, input_len))) {

        if ((command_start + 7) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "ENABLED", 7)) {
            return true;
        }

        if ((command_start + 10) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "CAPABILITY", 10)) {
            return true;
        }
    }
    return false;
}

static bool IMAPServerResponseMailboxStatus(const uint8_t *input, uint32_t input_len)
{
    /*mailbox status
     * https://datatracker.ietf.org/doc/html/rfc9051#name-mailbox-status
     * LIST
     * NAMESPACE
     * STATUS
     * SEARCH
     * FLAGS
     * These responses are always untagged.
     * */
    uint32_t command_start = 0;
    if ((command_start = IMAPUntaggedCmd(input, input_len))) {

        if ((command_start + 4) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "LIST", 4)) {
            return true;
        }

        if ((command_start + 9) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "NAMESPACE", 9)) {
            return true;
        }

        if ((command_start + 6) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "STATUS", 6)) {
            return true;
        }

        if ((command_start + 7) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "ESEARCH", 7)) {
            return true;
        }

        if ((command_start + 5) < input_len &&
                __IMAPCompareBytesToCmd(input + command_start, "FLAGS", 5)) {
            return true;
        }
    }
    return false;
}

static bool IMAPServerResponseMailboxSize(const uint8_t *input, uint32_t input_len)
{
    /*mailbox size
     * https://datatracker.ietf.org/doc/html/rfc9051#name-mailbox-size
     * EXISTS
     * These responses are always untagged.
     * */

    uint32_t mail_cnt_start = 0;
    if ((mail_cnt_start = IMAPUntaggedCmd(input, input_len))) {
        uint32_t command_start = 0;
        if ((command_start = __IMAPMailCount(input, input_len, mail_cnt_start))) {
            if ((command_start + 6) < input_len &&
                    __IMAPCompareBytesToCmd(input + command_start, "EXISTS", 6)) {
                return true;
            }
        }
    }
    return false;
}

static bool IMAPServerResponseMessageStatus(const uint8_t *input, uint32_t input_len)
{
    /*message status
     * https://datatracker.ietf.org/doc/html/rfc9051#name-message-status
     * EXPUNGE
     * FETCH
     * These responses are always untagged.
     * */

    uint32_t mail_cnt_start = 0;
    if ((mail_cnt_start = IMAPUntaggedCmd(input, input_len))) {
        uint32_t command_start = 0;
        if ((command_start = __IMAPMailCount(input, input_len, mail_cnt_start))) {
            if ((command_start + 7) < input_len &&
                    __IMAPCompareBytesToCmd(input + command_start, "EXPUNGE", 7)) {
                return true;
            }

            if ((command_start + 5) < input_len &&
                    __IMAPCompareBytesToCmd(input + command_start, "FETCH", 5)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * \brief Probe the input to see if it looks like imap check client commands.
 *
 * \retval ALPROTO_IMAP if it looks like imap, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto IMAPProbingParserTs(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    if (input_len < IMAP_MIN_FRAME_LEN) {
        goto not_imap;
    }

    uint16_t line_end;
    int ret = ByteExtractUint16(
            &line_end, BYTE_BIG_ENDIAN, sizeof(uint16_t), (const uint8_t *)(input + input_len - 2));
    if (ret == 0) {
        goto not_imap;
    }

    if (line_end != 0x0d0a /*CRLF*/) {
        goto not_imap;
    }

    /*
     * DONE command without tag.
     * */

    if (input_len == 6 && __IMAPCompareBytesToCmd(input, "DONE", 4)) {
        goto imap_detected;
    } else {
        /**
         *The client command begins an operation. Each client command is prefixed with an
         *identifier (typically a short alphanumeric string, e.g., A0001, A0002, etc.) called a
         *"tag".
         * */
        uint32_t command_start = 0;
        if (!(command_start = IMAPTaggedCmd(input, input_len))) {
            goto not_imap;
        }

        if (IMAPCmd(input, input_len, command_start)) {
            goto imap_detected;
        }
    }

not_imap:
    SCLogDebug("Protocol not detected as IMAP.");
    return ALPROTO_UNKNOWN;

imap_detected:
    SCLogDebug("Protocol detected as IMAP.");
    return ALPROTO_IMAP;
}

/**
 * \brief Probe the input to see if it looks like imap, checks server responses.
 *
 * \retval ALPROTO_IMAP if it looks like imap, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto IMAPProbingParserTc(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{

    if (input_len < IMAP_MIN_FRAME_LEN) {
        goto not_imap;
    }

    uint16_t line_end;
    int ret = ByteExtractUint16(
            &line_end, BYTE_BIG_ENDIAN, sizeof(uint16_t), (const uint8_t *)(input + input_len - 2));
    if (ret == 0) {
        goto not_imap;
    }

    if (line_end != 0x0d0a /*CRLF*/) {
        goto not_imap;
    }

    /**
     * after first token there is a single space then
     * generic status (OK, NO, BAD, PREAUTH, BYE)
     * server status (ENABLED, CAPABILITY)
     * mailbox status (LIST, NAMESPACE, STATUS, SEARCH, FLAGS)
     * mailbox size (EXISTS)
     * message status (EXPUNGE, FETCH)
     * */
    if (IMAPServerResponseGenericStatus(input, input_len)) {
        goto imap_detected;
    }

    if (IMAPServerResponseStatus(input, input_len)) {
        goto imap_detected;
    }

    if (IMAPServerResponseMailboxStatus(input, input_len)) {
        goto imap_detected;
    }

    if (IMAPServerResponseMailboxSize(input, input_len)) {
        goto imap_detected;
    }

    if (IMAPServerResponseMessageStatus(input, input_len)) {
        goto imap_detected;
    }

not_imap:
    SCLogDebug("Protocol not detected as IMAP.");
    return ALPROTO_UNKNOWN;

imap_detected:
    SCLogDebug("Protocol detected as IMAP.");
    return ALPROTO_IMAP;
}

void RegisterIMAPParsers(void)
{
    const char *proto_name = "imap";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogDebug("IMAP protocol detection is enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_IMAP, proto_name);

        if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_IMAP,
                    IMAP_MIN_FRAME_LEN, 0, IMAPProbingParserTs, IMAPProbingParserTc)) {
            SCLogDebug("No imap app-layer configuration, enabling imap"
                       " detection on port %s.",
                    IMAP_DEFAULT_PORT);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, IMAP_DEFAULT_PORT, ALPROTO_IMAP,
                    IMAP_MIN_FRAME_LEN, 0, STREAM_TOSERVER, IMAPProbingParserTs,
                    IMAPProbingParserTc);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, IMAP_DEFAULT_PORT, ALPROTO_IMAP,
                    IMAP_MIN_FRAME_LEN, 0, STREAM_TOCLIENT, IMAPProbingParserTc,
                    IMAPProbingParserTs);
        }

    } else {
        SCLogDebug("Protocol detector and parser disabled for IMAP.");
        return;
    }
}
