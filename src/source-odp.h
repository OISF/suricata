/* Copyright (C) 2016 Linaro
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
 * \author Maxim Uvarov <maxim.uvarov@linaro.org>
 *
 * OpenDataPlane ingress packet support
 */

#ifndef __SOURCE_ODP_H__
#define __SOURCE_ODP_H__

#ifdef HAVE_ODP
#include <odp_api.h>

typedef struct ODPIfaceConfig_
{
    SC_ATOMIC_DECLARE(unsigned int, threads);
} ODPIfaceConfig;

void TmModuleReceiveODPRegister(void);
void TmModuleDecodeODPRegister(void);

#endif /* HAVE_ODP */
#endif /* __SOURCE_ODP_H__ */
