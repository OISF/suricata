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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Address part of the detection engine.
 */

#ifndef __DETECT_ENGINE_IP_H__
#define __DETECT_ENGINE_IP_H__

struct AddrState {
    int state;
};

bool CheckAddress(const Address *a, const struct DetectAddresses *addrs);
bool CheckAddresses(const Packet *p, const Signature *s);
int DetectParseAddressesValidate(struct DetectAddresses *addrs, const char *str);
int DetectParseAddresses(
        const DetectEngineCtx *de_ctx, struct DetectAddresses *addrs, const char *str);
struct DetectAddresses DetectAddressesCopy(struct DetectAddresses *in_addrs);
struct DetectAddresses DetectParseAddress(DetectEngineCtx *de_ctx, const char *string);
void DetectAddressesClear(struct DetectAddresses *a);
bool DetectAddressesCompare(const struct DetectAddresses *a, const struct DetectAddresses *b);

#ifdef UNITTESTS
void DetectEngineIPRegisterTests(void);
#endif
#endif /* __DETECT_ENGINE_IP_H__ */
