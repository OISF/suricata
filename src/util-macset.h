/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 */

#ifndef __UTIL_MACSET_H__
#define __UTIL_MACSET_H__

typedef struct MacSet_ MacSet;
typedef enum {
    MAC_SET_SRC = 0,
    MAC_SET_DST
} MacSetSide;

typedef int (*MacSetIteratorFunc)(uint8_t *addr, MacSetSide side, void*);

MacSet *MacSetInit(int size);
void    MacSetAdd(MacSet*, uint8_t *src_addr, uint8_t *dst_addr);
void    MacSetAddWithCtr(MacSet*, uint8_t *src_addr, uint8_t *dst_addr, ThreadVars *tv,
                         uint16_t ctr_src, uint16_t ctr_dst);
int     MacSetForEach(const MacSet*, MacSetIteratorFunc, void*);
int     MacSetSize(const MacSet*);
void    MacSetReset(MacSet*);
void    MacSetFree(MacSet*);
void    MacSetRegisterFlowStorage(void);
FlowStorageId MacSetGetFlowStorageID(void);
bool    MacSetFlowStorageEnabled(void);
void    MacSetRegisterTests(void);

#endif /* __UTIL_MACSET_H__ */
