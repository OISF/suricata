/* Copyright (C) 2017-2022 Open Information Security Foundation
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
 */

#ifndef __DETECT_FTPDATA_H__
#define __DETECT_FTPDATA_H__

#include "app-layer-ftp.h"

/** Per keyword data. This is set up by the DetectFtpcommandSetup() function.
 *  Each signature will have an instance of DetectFtpcommandData per occurence
 *  of the keyword.
 *  The structure should be considered static/readonly after initialization.
 */
typedef struct DetectFtpdataData_ {
    FtpRequestCommand command;
} DetectFtpdataData;

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectFtpdataRegister(void);

#endif /* __DETECT_FTPDATA_H__ */
