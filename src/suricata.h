/* Copyright (C) 2007-2014 Open Information Security Foundation
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

/** \mainpage Doxygen documentation
 *
 * \section intro_sec Introduction
 *
 * The Suricata Engine is an Open Source Next Generation Intrusion Detection
 * and Prevention Engine. This engine is not intended to just replace or
 * emulate the existing tools in the industry, but will bring new ideas and
 * technologies to the field.
 *
 * \section dev_doc Developer documentation
 *
 * You've reach the automically generated documentation of Suricata. This
 * document contains information about architecture and code structure. It
 * is attended for developers wanting to understand or contribute to Suricata.
 *
 * \subsection modules Modules
 *
 * Documentation is generate from comments placed in all parts of the code.
 * But you will also find some groups describing specific functional parts:
 *  - \ref decode
 *  - \ref httplayer
 *  - \ref sigstate
 *  - \ref threshold
 *
 * \section archi Architecture
 *
 * \subsection datastruct Data structures
 *
 * Regarding matching, there is three main data structures which are:
 *  - ::Packet: Data relative to an individual packet with information about
 *  linked structure such as the ::Flow the ::Packet belongs to.
 *  - ::Flow: Information about a flow for example a TCP session
 *  - ::StreamMsg: structure containing the reassembled data
 *
 *  \subsection runmode Running mode
 *
 *  Suricata is multithreaded and running modes define how the different
 *  threads are working together. You can see util-runmodes.c for example
 *  of running mode.
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
#define PROG_VER "3.0dev"

/* workaround SPlint error (don't know __gnuc_va_list) */
#ifdef S_SPLINT_S
#  include <err.h>
#  define CONFIG_DIR "/etc/suricata"
#endif

#define DEFAULT_CONF_FILE CONFIG_DIR "/suricata.yaml"

#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_BASENAME "suricata.pid"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME

/* runtime engine control flags */
#define SURICATA_STOP    (1 << 0)   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define SURICATA_KILL    (1 << 1)   /**< shut down asap, discarding outstanding
                                     packets. */
#define SURICATA_DONE    (1 << 2)   /**< packets capture ended */

/* Engine stage/status*/
enum {
    SURICATA_INIT = 0,
    SURICATA_RUNTIME,
    SURICATA_DEINIT
};

/* Engine is acting as */
enum EngineMode {
    ENGINE_MODE_IDS,
    ENGINE_MODE_IPS,
};

void EngineModeSetIPS(void);
void EngineModeSetIDS(void);
int EngineModeIsIPS(void);
int EngineModeIsIDS(void);

/* Box is acting as router */
enum {
    SURI_HOST_IS_SNIFFER_ONLY,
    SURI_HOST_IS_ROUTER,
};

#define IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode)  ((host_mode) == SURI_HOST_IS_SNIFFER_ONLY)
#define IS_SURI_HOST_MODE_ROUTER(host_mode)  ((host_mode) == SURI_HOST_IS_ROUTER)

/* queue's between various other threads
 * XXX move to the TmQueue structure later
 */
PacketQueue trans_q[256];

SCDQDataQueue data_queues[256];

typedef struct SCInstance_ {
    int run_mode;

    char pcap_dev[128];
    char *sig_file;
    int sig_file_exclusive;
    char *pid_filename;
    char *regex_arg;

    char *keyword_info;
    char *runmode_custom_mode;
#ifndef OS_WIN32
    char *user_name;
    char *group_name;
    uint8_t do_setuid;
    uint8_t do_setgid;
    uint32_t userid;
    uint32_t groupid;
#endif /* OS_WIN32 */
    int delayed_detect;
    int disabled_detect;
    int daemon;
    int offline;
    int verbose;
    int checksum_validation;

    struct timeval start_time;

    char *log_dir;
} SCInstance;


/* memset to zeros, and mutex init! */
void GlobalInits();

extern volatile uint8_t suricata_ctl_flags;

/* uppercase to lowercase conversion lookup table */
uint8_t g_u8_lowercasetable[256];

extern char *conf_filename;

/* marco to do the actual lookup */
//#define u8_tolower(c) g_u8_lowercasetable[(c)]
// these 2 are slower:
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? g_u8_lowercasetable[(c)] : (c)
//#define u8_tolower(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c))

/* this is faster than the table lookup */
#include <ctype.h>
#define u8_tolower(c) tolower((uint8_t)(c))

void EngineStop(void);
void EngineKill(void);
void EngineDone(void);

/* live rule swap required this to be made static */
void SignalHandlerSigusr2(int);
void SignalHandlerSigusr2EngineShutdown(int);
void SignalHandlerSigusr2Idle(int sig);

int RunmodeIsUnittests(void);
int RunmodeGetCurrent(void);
int IsRuleReloadSet(int quiet);

extern int run_mode;

#endif /* __SURICATA_H__ */

