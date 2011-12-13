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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * The Cuda kernel for MPM B2G.
 *
 * \todo This is a basic version of the kernel.  Modify it to support multiple
 *       blocks of threads.  Make use of shared memory/texture memory.
 */

#define B2G_CUDA_Q 2
#define CUDA_THREADS 4000
#define B2G_CUDA_HASHSHIFT 4
#define B2G_CUDA_TYPE unsigned int
#define B2G_CUDA_HASH16(a, b) (((a) << B2G_CUDA_HASHSHIFT) | (b))
#define u8_tolower(c) g_u8_lowercasetable[(c)]

typedef struct SCCudaPBPacketDataForGPU_ {
    /* holds the value B2gCtx->m */
    unsigned int m;
    /* holds B2gCtx->B2g */
    unsigned int table;
    /* holds the length of the payload */
    unsigned int payload_len;
    /* holds the payload */
    unsigned char payload;
} SCCudaPBPacketDataForGPU;

extern "C"
__global__ void B2gCudaSearchBNDMq(unsigned short *results_buffer,
                                   unsigned char *packets_buffer,
                                   unsigned int *packets_offset_buffer,
                                   unsigned int *packets_payload_offset_buffer,
                                   unsigned int nop,
                                   unsigned char *g_u8_lowercasetable)
 {
    unsigned int tid = blockIdx.x * 32 + threadIdx.x;
    /* if the thread id is greater than the no of packets sent in the packets
     * buffer, terminate the thread */
    //if (tid <= nop)
    if (tid >= nop)
        return;

    SCCudaPBPacketDataForGPU *packet = (SCCudaPBPacketDataForGPU *)(packets_buffer + packets_offset_buffer[tid]);
    unsigned int m = packet->m;
    unsigned char *buf = &packet->payload;
    unsigned int buflen = packet->payload_len;
    unsigned int *B2G = (unsigned int *)packet->table;
    unsigned int pos = m - B2G_CUDA_Q + 1;
    B2G_CUDA_TYPE d;
    unsigned short h;
    unsigned int first;
    unsigned int j = 0;

    unsigned short *matches_count = results_buffer + packets_payload_offset_buffer[tid] + tid;
    //unsigned short *matches_count = results_buffer + packets_payload_offset_buffer[1] + 1;
    //unsigned short *offsets = results_buffer + packets_payload_offset_buffer[1] + 1 + 1;
    unsigned short *offsets = matches_count + 1;
    // temporarily hold the results here, before we shift it to matches_count
    // before returning
    unsigned short matches = 0;

    while (pos <= (buflen - B2G_CUDA_Q + 1)) {
        h = B2G_CUDA_HASH16(u8_tolower(buf[pos - 1]), u8_tolower(buf[pos]));
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
                        offsets[matches++] = j;
                    }
                }

                if (j == 0)
                    break;

                h = B2G_CUDA_HASH16(u8_tolower(buf[j - 1]), u8_tolower(buf[j]));
                d = (d << 1) & B2G[h];
            } while (d != 0);
        }
        pos = pos + m - B2G_CUDA_Q + 1;
    }

    matches_count[0] = matches;

    return;
}
