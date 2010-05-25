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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * The Cuda kernel for MPM B2G.
 *
 * \todo This is a basic version of the kernel.  Modify it to support multiple
 *       blocks of threads.  Make use of shared memory/texture memory.
 */

#define B2G_CUDA_Q 2
#define CUDA_THREADS 16
#define B2G_CUDA_HASHSHIFT 4
#define B2G_CUDA_TYPE unsigned int
#define B2G_CUDA_HASH16(a, b) (((a) << B2G_CUDA_HASHSHIFT) | (b))
#define u8_tolower(c) g_u8_lowercasetable[(c)]

extern "C"
__global__ void B2gCudaSearchBNDMq(unsigned int *offsets,
                                   unsigned int *B2G,
                                   unsigned char *g_u8_lowercasetable,
                                   unsigned char *buf,
                                   unsigned short arg_buflen,
                                   unsigned int m)
{
    unsigned int pos = m - B2G_CUDA_Q + 1;
    B2G_CUDA_TYPE d;
    unsigned short h;
    unsigned int j;
    unsigned int first;
    unsigned int tid = threadIdx.x;
    unsigned short tid_chunk = arg_buflen / CUDA_THREADS;
    unsigned short jump;
    unsigned short buflen;

    if (tid_chunk < m)
        tid_chunk = m;

    jump = tid_chunk * tid;
    if ((jump + tid_chunk) > arg_buflen)
        return;

    buflen = tid_chunk * 2 - 1;
    if ((tid == CUDA_THREADS - 1) || ((jump + buflen) > arg_buflen)) {
        buflen = arg_buflen - jump;
    }

    j = 0;
    while (j < buflen) {
        offsets[jump + j] = 0;
        j++;
    }

    while (pos <= (buflen - B2G_CUDA_Q + 1)) {
        h = B2G_CUDA_HASH16(u8_tolower(buf[jump + pos - 1]), u8_tolower(buf[jump + pos]));
        d = B2G[h];

        if (d != 0) {
            j = pos;
            first = pos - (m - B2G_CUDA_Q + 1);

            do {
                j = j - 1;
                if (d >= (1 << (m - 1))) {
                    if (j > first) {
                        pos = j;
                    } else {
                        offsets[j + jump] = 1;
                    }
                }

                if (j == 0)
                    break;

                h = B2G_CUDA_HASH16(u8_tolower(buf[jump + j - 1]), u8_tolower(buf[jump + j]));
                d = (d << 1) & B2G[h];
            } while (d != 0);
        }
        pos = pos + m - B2G_CUDA_Q + 1;
    }

    return;
}
