/* Copyright (C) 2011-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 */

#ifndef __SOURCE_MPIPE_H__
#define __SOURCE_MPIPE_H__

#ifdef HAVE_MPIPE

#include <gxio/mpipe.h>
#include <tmc/cpus.h>

#define MPIPE_FREE_PACKET(p) MpipeFreePacket((p))

#define MPIPE_COPY_MODE_NONE    0
#define MPIPE_COPY_MODE_TAP     1
#define MPIPE_COPY_MODE_IPS     2

#define MPIPE_IFACE_NAME_LENGTH 8

typedef struct MpipeIfaceConfig_
{
    char iface[MPIPE_IFACE_NAME_LENGTH];
    int copy_mode;
    char *out_iface;
} MpipeIfaceConfig;

typedef struct MpipePeer_
{
    int channel;
    char iface[MPIPE_IFACE_NAME_LENGTH];
} MpipePeer;

/* per interface TAP/IPS configuration */
typedef struct MpipePeerVars_
{
    gxio_mpipe_equeue_t *peer_equeue;
    void (*ReleasePacket)(struct Packet_ *);
    int copy_mode;
} MpipePeerVars;

/* per packet Mpipe vars */
typedef struct MpipePacketVars_
{
    /* TileGX mpipe stuff */
    struct {
        uint_reg_t channel : 5;
        uint_reg_t l2_size : 14;
        uint_reg_t size : 3;
        uint_reg_t bucket_id : 13;
        uint_reg_t nr : 1;
        uint_reg_t cs : 1;
        uint_reg_t va : 42;
        uint_reg_t stack_idx : 5;
    } idesc;

    /* packetpool this was allocated from */   
    uint8_t rank;

    gxio_mpipe_equeue_t *peer_equeue;
} MpipePacketVars;

int MpipeLiveRegisterDevice(char *);
int MpipeLiveGetDeviceCount(void);
char *MpipeLiveGetDevice(int);
void MpipeFreePacket(void *arg);
void TmModuleReceiveMpipeRegister (void);
void TmModuleDecodeMpipeRegister (void);

TmEcode ReceiveMpipeInit(void);

#endif /* HAVE_MPIPE */
#endif /* __SOURCE_MPIPE_H__ */
