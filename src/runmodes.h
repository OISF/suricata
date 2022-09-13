/* Copyright (C) 2007-2022 Open Information Security Foundation
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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __RUNMODES_H__
#define __RUNMODES_H__

/* Run mode */
enum RunModes {
    RUNMODE_UNKNOWN = 0,
    RUNMODE_PCAP_DEV,
    RUNMODE_PCAP_FILE,
    RUNMODE_PFRING,
    RUNMODE_NFQ,
    RUNMODE_NFLOG,
    RUNMODE_IPFW,
    RUNMODE_ERF_FILE,
    RUNMODE_DAG,
    RUNMODE_AFP_DEV,
    RUNMODE_AFXDP_DEV,
    RUNMODE_NETMAP,
    RUNMODE_DPDK,
    RUNMODE_UNITTEST,
    RUNMODE_NAPATECH,
    RUNMODE_UNIX_SOCKET,
    RUNMODE_WINDIVERT,
    RUNMODE_PLUGIN,
    RUNMODE_USER_MAX, /* Last standard running mode */
    RUNMODE_LIST_KEYWORDS,
    RUNMODE_LIST_APP_LAYERS,
    RUNMODE_LIST_RUNMODES,
    RUNMODE_PRINT_VERSION,
    RUNMODE_PRINT_BUILDINFO,
    RUNMODE_PRINT_USAGE,
    RUNMODE_DUMP_CONFIG,
    RUNMODE_CONF_TEST,
    RUNMODE_LIST_UNITTEST,
    RUNMODE_ENGINE_ANALYSIS,
#ifdef OS_WIN32
    RUNMODE_INSTALL_SERVICE,
    RUNMODE_REMOVE_SERVICE,
    RUNMODE_CHANGE_SERVICE_PARAMS,
#endif
    RUNMODE_DUMP_FEATURES,
    RUNMODE_MAX,
};

/* Run Mode Global Thread Names */
extern const char *thread_name_autofp;
extern const char *thread_name_single;
extern const char *thread_name_workers;
extern const char *thread_name_verdict;
extern const char *thread_name_flow_mgr;
extern const char *thread_name_flow_bypass;
extern const char *thread_name_flow_rec;
extern const char *thread_name_unix_socket;
extern const char *thread_name_detect_loader;
extern const char *thread_name_counter_stats;
extern const char *thread_name_counter_wakeup;

char *RunmodeGetActive(void);
const char *RunModeGetMainMode(void);

void RunModeListRunmodes(void);
void RunModeDispatch(int, const char *, const char *capture_plugin_name, const char *capture_plugin_args);
void RunModeRegisterRunModes(void);
void RunModeRegisterNewRunMode(enum RunModes, const char *, const char *,
                               int (*RunModeFunc)(void));
void RunModeInitialize(void);
void RunModeInitializeOutputs(void);
void RunModeShutDown(void);

/* bool indicating if file logger is enabled */
int RunModeOutputFileEnabled(void);
/* bool indicating if filedata logger is enabled */
int RunModeOutputFiledataEnabled(void);
/** bool indicating if run mode is offline */
bool IsRunModeOffline(enum RunModes run_mode_to_check);
bool IsRunModeSystem(enum RunModes run_mode_to_check);

void RunModeEnablesBypassManager(void);
int RunModeNeedsBypassManager(void);

extern int threading_set_cpu_affinity;
extern float threading_detect_ratio;
extern uint64_t threading_set_stack_size;

extern int debuglog_enabled;

#endif /* __RUNMODES_H__ */
