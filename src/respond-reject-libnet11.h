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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author William Metcalf <william.metcalf@gmail.com>
 */

#ifndef __RESPOND_REJECT_LIBNET11_H__
#define __RESPOND_REJECT_LIBNET11_H__

int RejectSendLibnet11IPv4TCP(ThreadVars *, Packet *, void *, enum RejectDirection);
int RejectSendLibnet11IPv4ICMP(ThreadVars *, Packet *, void *, enum RejectDirection);

int RejectSendLibnet11IPv6TCP(ThreadVars *, Packet *, void *, enum RejectDirection);
int RejectSendLibnet11IPv6ICMP(ThreadVars *, Packet *, void *, enum RejectDirection);

void FreeCachedCtx(void);

#endif /* __RESPOND_REJECT_LIBNET11_H__ */
