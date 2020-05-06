/* Copyright (C) 2011,2012 Open Information Security Foundation
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
 * \author Vadym Malakhatko <v.malakhatko@sirinsoftware.com>
 */
#ifndef __SOURCE_TESTIMONY_H__
#define __SOURCE_TESTIMONY_H__

#define SOCKET_NAME_LENGTH 256

typedef struct TestimonySocketConfig_
{
    char socket[SOCKET_NAME_LENGTH];
    /* fanout size */
    uint32_t fanout_size;
    /* each thread will connect to one fanout index */
    SC_ATOMIC_DECLARE(unsigned int, current_fanout_index);

    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} TestimonySocketConfig;

void TmModuleReceiveTestimonyRegister (void);
void TmModuleDecodeTestimonyRegister (void);

#endif /* __SOURCE_TESTIMONY_H__ */