/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Mike Pomraning <mpomraning@qualys.com>
 * \author Paulo Pacheco <fooinha@gmail.com>
 */

#ifndef __UTIL_LOGOPENFILE_H__
#define __UTIL_LOGOPENFILE_H__

#include "conf.h"            /* ConfNode   */
#include "tm-modules.h"      /* LogFileCtx */
#include "util-buffer.h"
#include "util-logopenfile-common.h"


LogFileCtx *LogFileNewCtx(void);
int LogFileFreeCtx(LogFileCtx *);
int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer);

int SCConfLogOpenGeneric(ConfNode *conf, LogFileCtx *, const char *, int);
#ifdef HAVE_LIBHIREDIS
int SCConfLogOpenRedis(ConfNode *conf, LogFileCtx *log_ctx);
#endif
int SCConfLogReopen(LogFileCtx *);

#endif /* __UTIL_LOGOPENFILE_H__ */
