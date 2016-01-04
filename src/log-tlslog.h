/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Roliers Jean-Paul <popof.fpn@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __LOG_TLSLOG_H__
#define __LOG_TLSLOG_H__

void TmModuleLogTlsLogRegister (void);

int TLSGetIPInformations(const Packet *p, char* srcip, size_t srcip_len,
                             Port* sp, char* dstip, size_t dstip_len,
                             Port* dp, int ipproto);

#endif /* __LOG_TLSLOG_H__ */

