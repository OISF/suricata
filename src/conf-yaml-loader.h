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

#ifndef SURICATA_CONF_YAML_LOADER_H
#define SURICATA_CONF_YAML_LOADER_H

#include "conf.h"

int SCConfYamlLoadFile(const char *);
int SCConfYamlLoadString(const char *, size_t);
int SCConfYamlLoadFileWithPrefix(const char *filename, const char *prefix);
int SCConfYamlHandleInclude(SCConfNode *parent, const char *filename);

void SCConfYamlRegisterTests(void);

#endif /* !SURICATA_CONF_YAML_LOADER_H */
