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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __SURICATA_H__
#define __SURICATA_H__

#include "suricata-common.h"
#include "packet-queue.h"
#include "data-queue.h"

/* the name of our binary */
#define PROG_NAME "Suricata"
#define PROG_VER "1.0.4"

/* runtime engine control flags */
#define SURICATA_STOP    0x01   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define SURICATA_KILL    0x02   /**< shut down asap, discarding outstanding
                                     packets. */

/* Run mode */
enum {
    MODE_UNKNOWN = 0,
    MODE_PCAP_DEV,
    MODE_PCAP_FILE,
    MODE_PFRING,
    MODE_NFQ,
    MODE_IPFW,
    MODE_UNITTEST,
    MODE_ERF_FILE,
    MODE_DAG,
};

/* Engine stage/status*/
enum {
    SURICATA_INIT = 0,
    SURICATA_RUNTIME,
    SURICATA_DEINIT
};

/* Engine is acting as */
enum {
    ENGINE_MODE_IDS,
    ENGINE_MODE_IPS,
};

/** You can use this macros to set/check if we have real drop capabilities */
#define SET_ENGINE_MODE_IPS(engine_mode) (engine_mode = ENGINE_MODE_IPS);
#define SET_ENGINE_MODE_IDS(engine_mode) (engine_mode = ENGINE_MODE_IDS);
#define IS_ENGINE_MODE_IPS(engine_mode) (engine_mode == ENGINE_MODE_IPS)
#define IS_ENGINE_MODE_IDS(engine_mode) (engine_mode == ENGINE_MODE_IDS)

/* queue's between various other threads
 * XXX move to the TmQueue structure later
 */
PacketQueue trans_q[256];

SCDQDataQueue data_queues[256];
/* memset to zeros, and mutex init! */
void GlobalInits();

/* uppercase to lowercase conversion lookup table */
uint8_t g_u8_lowercasetable[256];
/* marco to do the actual lookup */
#define u8_tolower(c) g_u8_lowercasetable[(c)]
// these 2 are slower:
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? g_u8_lowercasetable[(c)] : (c)
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c)

void EngineStop(void);
void EngineKill(void);

int RunmodeIsUnittests(void);

#endif /* __SURICATA_H__ */

