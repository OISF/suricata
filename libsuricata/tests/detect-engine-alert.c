/* Copyright (C) 2022 Open Information Security Foundation
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

#include "../suricata-common.h"

#include "../detect.h"
#include "../detect-engine.h"
#include "../detect-engine-alert.h"
#include "../detect-parse.h"

#include "../util-unittest.h"
#include "../util-unittest-helper.h"

/**
 * \brief Tests that the reject action is correctly set in Packet->action
 */
static int TestDetectAlertPacketApplySignatureActions01(void)
{
#ifdef HAVE_LIBNET11
    uint8_t payload[] = "Hi all!";
    uint16_t length = sizeof(payload) - 1;
    Packet *p = UTHBuildPacketReal(
            (uint8_t *)payload, length, IPPROTO_TCP, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(p);

    const char sig[] = "reject tcp any any -> any 80 (content:\"Hi all\"; sid:1; rev:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);
    FAIL_IF_NOT(PacketTestAction(p, ACTION_REJECT_ANY));

    UTHFreePackets(&p, 1);
#endif /* HAVE_LIBNET11 */
    PASS;
}

/**
 * \brief Tests that the packet has the drop action correctly updated in Packet->action
 */
static int TestDetectAlertPacketApplySignatureActions02(void)
{
    uint8_t payload[] = "Hi all!";
    uint16_t length = sizeof(payload) - 1;
    Packet *p = UTHBuildPacketReal(
            (uint8_t *)payload, length, IPPROTO_TCP, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(p);

    const char sig[] = "drop tcp any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);
    FAIL_IF_NOT(PacketTestAction(p, ACTION_DROP));

    UTHFreePackets(&p, 1);
    PASS;
}

/**
 * \brief Registers Detect Engine Alert unit tests
 */
void DetectEngineAlertRegisterTests(void)
{
    UtRegisterTest("TestDetectAlertPacketApplySignatureActions01",
            TestDetectAlertPacketApplySignatureActions01);
    UtRegisterTest("TestDetectAlertPacketApplySignatureActions02",
            TestDetectAlertPacketApplySignatureActions02);
}
