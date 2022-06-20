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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __UTIL_PROTO_NAME_H__
#define	__UTIL_PROTO_NAME_H__

/** Lookup array to hold the information related to known protocol
 *  values
 */
extern const char *known_proto[256];

bool SCProtoNameValid(uint8_t);
bool SCGetProtoByName(const char *protoname, uint8_t *proto_number);
void SCProtoNameInit(void);
void SCProtoNameRelease(void);

#ifdef UNITTESTS
void SCProtoNameRegisterTests(void);
#endif

#endif	/* __UTIL_PROTO_NAME_H__ */

