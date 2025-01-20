/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine-register.h"
#include "detect-ssh-software-version.h"

static int DetectSshSoftwareVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogError("ssh.softwareversion is obsolete, use now ssh.software");
    return -1;
}

/**
 * \brief Registration function for keyword: ssh.softwareversion
 */
void DetectSshSoftwareVersionRegister(void)
{
    sigmatch_table[DETECT_SSH_SOFTWAREVERSION].name = "ssh.softwareversion";
    sigmatch_table[DETECT_SSH_SOFTWAREVERSION].desc = "obsolete keyword, use now ssh.software";
    sigmatch_table[DETECT_SSH_SOFTWAREVERSION].Setup = DetectSshSoftwareVersionSetup;
}
