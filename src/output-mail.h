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
 * AppLayer Mail Logger Output registration functions
 */

#ifndef __OUTPUT_MAIL_H__
#define __OUTPUT_MAIL_H__

#include "decode.h"
#include "util-file.h"

/** packet logger function pointer type */
typedef int (*MailLogger)(ThreadVars *, void *thread_data, const Packet *, const File *);

int OutputRegisterMailLogger(const char *name, MailLogger LogFunc, OutputCtx *);

void TmModuleMailLoggerRegister (void);

void OutputMailShutdown(void);

#endif /* __OUTPUT_MAIL_H__ */
