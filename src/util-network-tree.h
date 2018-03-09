/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 */

#ifndef UTIL_NETWORK_TREE_H_
#define UTIL_NETWORK_TREE_H_

void NetworkTreeInit(void);
void NetworkTreeDeInit(void);
void NetworkTreeLoadConfig(void);
void NetworkTreeLoadConfigMultiTenant(DetectEngineCtx *de_ctx);
json_t *NetworkTreeGetIPv4InfoAsJSON(uint8_t *ipv4_addr, int tenant_id);
json_t *NetworkTreeGetIPv6InfoAsJSON(uint8_t *ipv6_addr, int tenant_id);
int NetworkTreeMoveToFreeList(DetectEngineCtx *de_ctx);
void NetworkTreePruneFreeList(void);
void NetworkTreeRegisterTests(void);

#ifdef UNITTESTS
void NetworkTreeInitForTests(json_t *networkjs);
void NetworkTreeDoRegisterTests(void);
#endif /* UNITTESTS */

#endif /* UTIL_NETWORK_TREE_H_ */

