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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *         Based on FMem.c of Alexandre Flori (2008/10/17 AF)
 */

#ifndef __FMEMOPEN_H__
#define __FMEMOPEN_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include this file only for OSX / BSD compilations */
#ifdef OS_DARWIN
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_FREEBSD
#define USE_FMEM_WRAPPER 1
#endif

#ifdef __OpenBSD__
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_WIN32
#define USE_FMEM_WRAPPER 1
#endif

#ifdef USE_FMEM_WRAPPER
FILE *SCFmemopen(void *, size_t, const char *);
#else
/* Else use the normal fmemopen */
#define SCFmemopen fmemopen
#endif

#endif /* __FMEMOPEN_H__ */
