/* Copyright (C) 2020 Open Information Security Foundation
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

#ifndef __MACSET_H__
#define __MACSET_H__

#include <stdint.h>

typedef struct MacSet_ MacSet;

typedef int (*MacSetIteratorFunc)(uint8_t *addr, int direction, void*);

MacSet*       MacSetInit(int size);
void          MacSetAdd(MacSet*, uint8_t *addr, int direction);
int           MacSetForEach(MacSet*, MacSetIteratorFunc, void*);
unsigned long MacSetSize(MacSet*);
void          MacSetReset(MacSet*);
void          MacSetFree(MacSet*);

#endif /* __MACSET_H__ */