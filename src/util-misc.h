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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_MISC_H__
#define __UTIL_MISC_H__

#include "util-error.h"

/**
 * \brief Generic API that can be used by all to log an
 *        invalid conf entry.
 * \param param_name A string specifying the param name.
 * \param format Format for the below value.  For example "%s", "%"PRIu32,
                 etc.
 * \param value Default value to be printed.
 */
#define WarnInvalidConfEntry(param_name, format, value) do {            \
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY,                    \
                     "Invalid conf entry found for "                    \
                     "\"%s\".  Using default value of \"" format "\".", \
                     param_name, value);                                \
    } while (0)

/* size string parsing API */

int ParseSizeStringU8(const char *, uint8_t *);
int ParseSizeStringU16(const char *, uint16_t *);
int ParseSizeStringU32(const char *, uint32_t *);
int ParseSizeStringU64(const char *, uint64_t *);
void UtilMiscRegisterTests(void);

void ParseSizeInit(void);
void ParseSizeDeinit(void);

#endif /* __UTIL_MISC_H__ */
