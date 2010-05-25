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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#define COUNTER_STREAMTCP_STREAMS 1

#define STREAM_VERBOSE    FALSE
/*global flow data*/
typedef struct TcpStreamCnf_ {
    uint32_t memcap; /** max stream mem usage */
    int max_sessions;
    int prealloc_sessions;
    int midstream;
    int async_oneside;
} TcpStreamCnf;

TcpStreamCnf stream_config;
void TmModuleStreamTcpRegister (void);
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpIncrMemuse(uint32_t);
void StreamTcpDecrMemuse(uint32_t);
int StreamTcpCheckMemcap(uint32_t);

#endif /* __STREAM_TCP_H__ */

