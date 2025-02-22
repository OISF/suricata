/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Jim Xu <jim.xu@windriver.com>
 * \author Justin Viiret <justin.viiret@intel.com>
 *
 * MPM pattern matcher that calls the Hyperscan regex matcher.
 */

#ifndef SURICATA_UTIL_MPM_HS__H
#define SURICATA_UTIL_MPM_HS__H

void MpmHSRegister(void);

void MpmHSGlobalCleanup(void);

#endif /* SURICATA_UTIL_MPM_HS__H */
