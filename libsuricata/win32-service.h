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
 * \author Ondrej Slanina <oslanina@kerio.com>
 */

#ifndef __WIN32_SERVICE_H__
#define __WIN32_SERVICE_H__

#ifdef OS_WIN32
int SCRunningAsService(void);
int SCServiceInit(int argc, char **argv);
int SCServiceInstall(int argc, char **argv);
int SCServiceRemove(int argc, char **argv);
int SCServiceChangeParams(int argc, char **argv);
#endif /* OS_WIN32 */

#endif
