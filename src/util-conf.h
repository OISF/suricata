/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 */

#ifndef __UTIL_UTIL_CONF_H__
#define __UTIL_UTIL_CONF_H__

#include "conf.h"

TmEcode ConfigSetLogDirectory(const char *name);
const char *ConfigGetLogDirectory(void);
TmEcode ConfigCheckLogDirectoryExists(const char *log_dir);

TmEcode ConfigSetDataDirectory(char *name);
const char *ConfigGetDataDirectory(void);
TmEcode ConfigCheckDataDirectory(const char *log_dir);

ConfNode *ConfFindDeviceConfig(ConfNode *node, const char *iface);

int ConfUnixSocketIsEnable(void);

#endif /* __UTIL_UTIL_CONF_H__ */
