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

#ifndef __UTIL_PLUGIN_H__
#define __UTIL_PLUGIN_H__

#include "suricata-plugin.h"

void SCPluginsLoad(const char *capture_plugin_name, const char *capture_plugin_args);
SCEveFileType *SCPluginFindFileType(const char *name);
SCCapturePlugin *SCPluginFindCaptureByName(const char *name);

bool RegisterPlugin(SCPlugin *, void *);

#endif /* __UTIL_PLUGIN_H__ */
