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
 *
 * The Cuda kernel for MPM AC.
 *
 * \todo - This is a basic version of the kernel.
 *       - Support 16 bit state tables.
 *       - Texture memory.
 *       - Multiple threads per blocks of threads.  Make use of
 *         shared memory/texture memory.
 */

extern "C"
__global__ void SCACCudaSearch64(unsigned char *d_buffer,
                                 unsigned int d_buffer_start_offset,
                                 unsigned int *o_buffer,
                                 unsigned int *results_buffer,
                                 unsigned int nop,
                                 unsigned char *tolower)
{
    unsigned int u = 0;
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= nop)
        return;

    unsigned int buflen = *((unsigned long *)(d_buffer + (o_buffer[tid] - d_buffer_start_offset)));
    unsigned int (*state_table_u32)[256] =
        (unsigned int (*)[256])*((unsigned long *)(d_buffer + (o_buffer[tid] - d_buffer_start_offset) + 8));
    unsigned char *buf = (d_buffer + (o_buffer[tid] - d_buffer_start_offset) + 16);

    unsigned int state = 0;
    unsigned int matches = 0;
    unsigned int *results = (results_buffer + ((o_buffer[tid] - d_buffer_start_offset) * 2) + 1);
    for (u = 0; u < buflen; u++) {
        state = state_table_u32[state & 0x00FFFFFF][tolower[buf[u]]];
        if (state & 0xFF000000) {
            results[matches++] = u;
            results[matches++] = state & 0x00FFFFFF;
        }
    }

    *(results - 1) = matches;
    return;
}

extern "C"
__global__ void SCACCudaSearch32(unsigned char *d_buffer,
                                 unsigned int d_buffer_start_offset,
                                 unsigned int *o_buffer,
                                 unsigned int *results_buffer,
                                 unsigned int nop,
                                 unsigned char *tolower)
{
    unsigned int u = 0;
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= nop)
        return;

    unsigned int buflen = *((unsigned int *)(d_buffer + (o_buffer[tid] - d_buffer_start_offset)));
    unsigned int (*state_table_u32)[256] =
        (unsigned int (*)[256])*((unsigned int *)(d_buffer + (o_buffer[tid] - d_buffer_start_offset) + 4));
    unsigned char *buf = (d_buffer + (o_buffer[tid] - d_buffer_start_offset) + 8);

    unsigned int state = 0;
    unsigned int matches = 0;
    unsigned int *results = (results_buffer + ((o_buffer[tid] - d_buffer_start_offset) * 2) + 1);
    for (u = 0; u < buflen; u++) {
        state = state_table_u32[state & 0x00FFFFFF][tolower[buf[u]]];
        if (state & 0xFF000000) {
            results[matches++] = u;
            results[matches++] = state & 0x00FFFFFF;
        }
    }

    *(results - 1) = matches;
    return;
}
