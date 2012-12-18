/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_CUDA_HANDLERS__H__
#define __UTIL_CUDA_HANDLERS__H__

#include "conf.h"
#include "util-cuda.h"

/************************conf file profile section**********************/

void CudaHL_AddCudaProfileFromConf(const char *name,
                                   void *(*Callback)(ConfNode *node),
                                   void (*Free)(void *));
void *CudaHL_GetCudaProfile(const char *name);
void CudaHL_FreeProfiles(void);

/*******************cuda context related data section*******************/

#define CUDAHL_MODULE_DATA_TYPE_MEMORY_HOST 0
#define CUDAHL_MODULE_DATA_TYPE_MEMORY_DEVICE 1
#define CUDAHL_MODULE_DATA_TYPE_MTSBA 2

CUcontext CudaHL_Module_GetContext(const char *module_name, int device_id);
void CudaHL_Module_StoreData(const char *module_name,
                             const char *data_name, void *data_ptr);
void *CudaHL_Module_GetData(const char *module_name, const char *data_name);
int CudaHL_GetCudaModule(CUmodule *p_module, const char *ptx_image);

#endif /* __UTIL_CUDA_HANDLERS__H__ */

