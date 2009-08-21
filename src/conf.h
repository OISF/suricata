/* Copyright (c) 2009 Open Information Security Foundation
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \author Endace Technology Limited
 */

#ifndef __CONF_H__
#define __CONF_H__

/**
 * The default log directory.
 */
#define DEFAULT_LOG_DIR "/var/log/eidps"

void ConfInit(void);
int ConfGet(char *name, char **vptr);
int ConfSet(char *name, char *val, int allow_override);
void ConfRegisterTests();

#endif /* ! __CONF_H__ */
