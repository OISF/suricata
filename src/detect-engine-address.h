/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_ADDRESS_H
#define SURICATA_DETECT_ADDRESS_H

DetectAddress *DetectAddressInit(void);
void DetectAddressFree(DetectAddress *);
DetectAddress *DetectAddressCopy(DetectAddress *);
int DetectAddressParse(const DetectEngineCtx *, DetectAddressHead *, const char *);
void DetectAddressHeadCleanup(DetectAddressHead *);
void DetectAddressCleanupList(DetectAddress *head);

bool DetectAddressListsAreEqual(DetectAddress *list1, DetectAddress *list2);

DetectAddress *DetectAddressLookupInHead(const DetectAddressHead *, Address *);

int DetectAddressCmp(DetectAddress *, DetectAddress *);

int DetectAddressMatchIPv4(const DetectMatchAddressIPv4 *, uint16_t, const Address *);
int DetectAddressMatchIPv6(const DetectMatchAddressIPv6 *, uint16_t, const Address *);

int DetectAddressTestConfVars(void);

void DetectAddressTests(void);

int DetectAddressMapInit(DetectEngineCtx *de_ctx);
void DetectAddressMapFree(DetectEngineCtx *de_ctx);
const DetectAddressHead *DetectParseAddress(DetectEngineCtx *de_ctx,
        const char *string, bool *contains_negation);

#endif /* SURICATA_DETECT_ADDRESS_H */
