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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 */

#ifndef __CONF_YAML_LOADER_H__
#define __CONF_YAML_LOADER_H__

#include "rust-config.h"

int ConfYamlLoadFile(const char *);
int ConfYamlLoadString(const char *, size_t);
int ConfYamlLoadFileWithPrefix(const char *filename, const char *prefix);
void ConfNodeFromYaml(Yaml *yaml, ConfNode *root, bool);

void ConfYamlRegisterTests(void);

#endif /* !__CONF_YAML_LOADER_H__ */
