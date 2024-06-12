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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef SURICATA_UTIL_CPU_H
#define SURICATA_UTIL_CPU_H

/* Processors configured: */
uint16_t UtilCpuGetNumProcessorsConfigured(void);
/* Processors online: */
uint16_t UtilCpuGetNumProcessorsOnline(void);

void UtilCpuPrintSummary(void);

uint64_t UtilCpuGetTicks(void);

#ifdef __sparc
void EnableSparcMisalignEmulation(void);
#endif /* __sparc */

#endif /* SURICATA_UTIL_CPU_H */
