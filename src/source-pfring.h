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
 * \author William Metcalf <william.metcalf@gmail.com>
 */

#ifndef __SOURCE_PFRING_H__
#define __SOURCE_PFRING_H__

void TmModuleReceivePfringRegister (void);
void TmModuleDecodePfringRegister (void);

/* XXX replace with user configurable options */
#define LIBPFRING_SNAPLEN     1518
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1
#endif /* __SOURCE_PFRING_H__ */
