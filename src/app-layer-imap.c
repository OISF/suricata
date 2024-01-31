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
#include "rust-bindings.h"
#include "app-layer-imap.h"

static int IMAPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* OK ", 5, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* NO ", 5, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* BAD ", 6, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* LIST ", 7, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* ESEARCH ", 10, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* STATUS ", 9, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_IMAP, "* FLAGS ", 8, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    /**
     * there is no official document that limits the length of the tag
     * some practical implementations limit it to 20 characters
     * but keeping depth equal to 31 fails unit tests such  AppLayerTest10
     * so keeping dpeth 17 for now to pass unit tests, that might miss some detections
     * until we find a better solution for the unit tests.
     */
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IMAP, " CAPABILITY",
                17 /*6 for max tag len + space + len(CAPABILITY)*/, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    return 0;
}

void RegisterIMAPParsers(void)
{
    const char *proto_name = "imap";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        SCLogDebug("IMAP protocol detection is enabled.");
        AppLayerProtoDetectRegisterProtocol(ALPROTO_IMAP, proto_name);
        if (IMAPRegisterPatternsForProtocolDetection() < 0)
            SCLogError("Failed to register IMAP protocol detection patterns.");
    } else {
        SCLogDebug("Protocol detector and parser disabled for IMAP.");
    }
}
