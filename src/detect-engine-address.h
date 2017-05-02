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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* prototypes */
void DetectAddressRegister (void);

DetectAddressHead *DetectAddressHeadInit(void);
void DetectAddressHeadFree(DetectAddressHead *);
void DetectAddressHeadCleanup(DetectAddressHead *);

int DetectAddressParseString(DetectAddress *, const char *);
int DetectAddressParse(const DetectEngineCtx *, DetectAddressHead *, const char *);

DetectAddress *DetectAddressInit(void);
void DetectAddressFree(DetectAddress *);

void DetectAddressCleanupList (DetectAddress *);
int DetectAddressAdd(DetectAddress **, DetectAddress *);
void DetectAddressPrintList(DetectAddress *);

int DetectAddressInsert(DetectEngineCtx *, DetectAddressHead *, DetectAddress *);
int DetectAddressJoin(DetectEngineCtx *, DetectAddress *, DetectAddress *);

DetectAddress *DetectAddressLookupInHead(const DetectAddressHead *, Address *);
DetectAddress *DetectAddressLookupInList(DetectAddress *, DetectAddress *);
int DetectAddressMatch(DetectAddress *, Address *);

DetectAddress *DetectAddressCopy(DetectAddress *);
void DetectAddressPrint(DetectAddress *);
int DetectAddressCmp(DetectAddress *, DetectAddress *);

int DetectAddressMatchIPv4(DetectMatchAddressIPv4 *, uint16_t, Address *);
int DetectAddressMatchIPv6(DetectMatchAddressIPv6 *, uint16_t, Address *);

int DetectAddressTestConfVars(void);

void DetectAddressTests(void);

int DetectAddressMapInit(DetectEngineCtx *de_ctx);
void DetectAddressMapFree(DetectEngineCtx *de_ctx);
const DetectAddressHead *DetectParseAddress(DetectEngineCtx *de_ctx,
        const char *string);

#endif /* __DETECT_ADDRESS_H__ */
