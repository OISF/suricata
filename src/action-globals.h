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
 */

#ifndef __ACTION_GLOBALS_H__
#define __ACTION_GLOBALS_H__

#define NUMBER_OF_ACTIONS 4

/* Changing them as flags, so later we can have alerts
 * and drop simultaneously */
#define ACTION_ALERT        BIT_U8(0)
#define ACTION_DROP         BIT_U8(1)
#define ACTION_REJECT       BIT_U8(2)
#define ACTION_REJECT_DST   BIT_U8(3)
#define ACTION_REJECT_BOTH  BIT_U8(4)
#define ACTION_PASS         BIT_U8(5)

#endif /* __ACTION_GLOBALS_H__ */
