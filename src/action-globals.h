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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __ACTION_GLOBALS_H__
#define __ACTION_GLOBALS_H__

/* Changing them as flags, so later we can have alerts
 * and drop simultaneously */
#define ACTION_ALERT        0x01
#define ACTION_DROP         0x02
#define ACTION_REJECT       0x04
#define ACTION_REJECT_DST   0x08
#define ACTION_REJECT_BOTH  0x10
#define ACTION_PASS         0x20
#define ACTION_CONFIG       0x40

#define ACTION_REJECT_ANY   (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)

#endif /* __ACTION_GLOBALS_H__ */
