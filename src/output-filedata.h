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
 * \author Victor Julien <victor@inliniac.net>
 *
 * AppLayer Filedata Logger Output registration functions
 */

#ifndef __OUTPUT_FILEDATA_H__
#define __OUTPUT_FILEDATA_H__

#include "decode.h"
#include "util-file.h"

#define OUTPUT_FILEDATA_FLAG_OPEN  0x01
#define OUTPUT_FILEDATA_FLAG_CLOSE 0x02

/** filedata logger function pointer type */
typedef int (*FiledataLogger)(ThreadVars *, void *thread_data, const Packet *,
        const File *, const FileData *, uint8_t);

/** packet logger condition function pointer type,
 *  must return true for packets that should be logged
 */
//typedef int (*TxLogCondition)(ThreadVars *, const Packet *);

int OutputRegisterFiledataLogger(const char *name, FiledataLogger LogFunc, OutputCtx *);

void TmModuleFiledataLoggerRegister (void);

void OutputFiledataShutdown(void);

#endif /* __OUTPUT_FILE_H__ */
