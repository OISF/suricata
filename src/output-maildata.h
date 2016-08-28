/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * AppLayer Maildata Logger Output registration functions
 */

#ifndef __OUTPUT_MAILDATA_H__
#define __OUTPUT_MAILDATA_H__

#include "decode.h"
#include "util-file.h"

#define OUTPUT_MAILDATA_FLAG_OPEN  0x01
#define OUTPUT_MAILDATA_FLAG_CLOSE 0x02

/** maildata logger function pointer type */
typedef int (*MaildataLogger)(ThreadVars *, void *thread_data, const Packet *,
        const File *, const uint8_t *, uint32_t, uint8_t);

int OutputRegisterMaildataLogger(const char *name, MaildataLogger LogFunc, OutputCtx *);

void TmModuleMaildataLoggerRegister (void);

void OutputMaildataShutdown(void);

#endif /* __OUTPUT_MAILDATA_H__ */
