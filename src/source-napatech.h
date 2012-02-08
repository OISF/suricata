/* Copyright (C) 2010 Open Information Security Foundation
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
 * \author nPulse Technologies, LLC
 * \author Randy Caldejon <rc@npulsetech.com>
 */

#ifndef __SOURCE_NAPATECH_H__
#define __SOURCE_NAPATECH_H__

void TmModuleNapatechFeedRegister (void);
TmEcode NapatechFeedThreadDeinit(ThreadVars *tv, void *data);
void TmModuleNapatechDecodeRegister (void);

#ifdef HAVE_NAPATECH

#include "ntfeeds.h"

#endif

#endif /* __SOURCE_NAPATECH_H__ */
