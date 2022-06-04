/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#define _POSIX_C_SOURCE 200809L
#define CLS             64 // sysconf(_SC_LEVEL1_DCACHE_LINESIZE)
#include <getopt.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "prefilter.h"
#include "util-prefilter.h"
#include "logger.h"
#include "logger-basic.h"

#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "lcores-manager.h"
#include "lcore-worker.h"
#include "stats.h"

struct prefilter_args {
    char *conf_path;
    LogLevelEnum log_lvl;
};

struct ctx_global_resource ctx = { 0 };

static void EalInit(int *argc, char ***argv)
{
    int args;

    rte_log_set_global_level(RTE_LOG_WARNING);
    args = rte_eal_init(*argc, *argv);
    if (args < 0) {
        fprintf(stderr, "rte_eal_init() has failed: %d\n", args);
        exit(EXIT_FAILURE);
    }
    *argc -= args;
    *argv += args;

    if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        fprintf(stderr, "invalid process type, primary required\n");
        rte_eal_cleanup();
        exit(EXIT_FAILURE);
    }
}

static void PrintUsage()
{
    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t--config-path <path>                            : path to configuration file\n");
    printf("\t-l <log-level>                            : level of logs\n");
    printf("\t--log-level <log-level>                            : level of logs\n");
}

static int ArgsParse(int argc, char *argv[], struct prefilter_args *args)
{
    int opt;

    // clang-format off
struct option long_opts[] = {
#ifdef HAVE_DPDK
{"config-path", required_argument, 0, 0},
{"log-level", required_argument, 0, 0},
#endif
};
    // clang-format on

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:l:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp((long_opts[option_index]).name, "config-path") == 0) {
                    args->conf_path = optarg;
                    break;
                } else if (strcmp((long_opts[option_index]).name, "log-level") == 0) {
                    args->log_lvl = LoggerGetLogLevelFromString(optarg);
                    break;
                }
                PrintUsage();
                return -EXIT_FAILURE;
            case 'c':
                args->conf_path = optarg;
                break;
            case 'l':
                args->log_lvl = LoggerGetLogLevelFromString(optarg);
                break;
            default:
                PrintUsage();
                return -EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int IPCActionAttach(const struct rte_mp_msg *msg, const void *peer)
{
    struct rte_mp_msg mp_resp;
    int ret;
    struct IPCResponseAttach *a;
    uint8_t tout_sec = 5;

    Log().debug("Action for %s", IPC_ACTION_ATTACH);
    ret = LcoreStateCheckAllWTimeout(LCORE_WAIT, tout_sec);
    if (ret != 0) {
        Log().error(ETIMEDOUT, "Workers not found in the wait state in time (%s sec)", tout_sec);
        exit(1);
    }

    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name));
    mp_resp.len_param = sizeof(*a);
    a = (struct IPCResponseAttach *)mp_resp.param;
    a->app_id = 0;
    strlcpy(a->memzone_name, ctx.shared_conf->name, sizeof(a->memzone_name));
    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_INIT);
        }
    } else {
        Log().warning(ENOTSUP, "Unable to reply (%s)", rte_strerror(rte_errno));
        return -1;
    }

    Log().notice("App has attached to Prefilter");
    return 0;
}

static int IPCActionDetach(const struct rte_mp_msg *msg, const void *peer)
{
    struct rte_mp_msg mp_resp;
    int ret;
    Log().debug("Action for %s", IPC_ACTION_DETACH);

    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name) / sizeof(mp_resp.name[0]));
    strlcpy((char *)mp_resp.param, IPC_VALID_RESPONSE, sizeof(mp_resp.param) / sizeof(mp_resp.param[0]));
    mp_resp.len_param = (int)strlen((char *)mp_resp.param);

    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_DETACH);
        }
    } else {
        Log().warning(ENOTSUP, "Unable to reply (%s)", rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

static int IPCActionPktsStart(const struct rte_mp_msg *msg, const void *peer)
{
    struct rte_mp_msg mp_resp;
    int ret;
    Log().debug("Action for %s", IPC_ACTION_START);

    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name) / sizeof(mp_resp.name[0]));
    strlcpy((char *)mp_resp.param, IPC_VALID_RESPONSE, sizeof(mp_resp.param) / sizeof(mp_resp.param[0]));
    mp_resp.len_param = (int)strlen((char *)mp_resp.param);

    uint8_t tout_sec = 5;
    ret = LcoreStateCheckAllWTimeout(LCORE_INIT_DONE, tout_sec);
    if (ret != 0) {
        Log().error(ETIMEDOUT, "Workers has not initialised in time (%s sec)", tout_sec);
        exit(1);
    }

    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state,LCORE_RUN);
        }
    } else {
        Log().warning(ENOTSUP, "Error (%s): Unable to reply for action %s",
                rte_strerror(rte_errno), IPC_ACTION_START);
        return -1;
    }

    return 0;
}

static int IPCActionPktsStop(const struct rte_mp_msg *msg, const void *peer)
{
    struct rte_mp_msg mp_resp;
    int ret;
    Log().debug("Action for %s", IPC_ACTION_STOP);

    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name));
    strlcpy((char *)mp_resp.param, IPC_VALID_RESPONSE, sizeof(mp_resp.param));
    mp_resp.len_param = (int)strlen((char *)mp_resp.param);

    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        StopWorkers();

        uint8_t tout_sec = 5;
        ret = LcoreStateCheckAllWTimeout(LCORE_RUNNING_DONE, tout_sec);
        if (ret != 0) {
            Log().error(ETIMEDOUT, "Workers has not finished in time (%s sec)", tout_sec);
            exit(1);
        }
    } else {
        Log().warning(ENOTSUP, "Error (%s): Unable to reply for action %s",
                rte_strerror(rte_errno), IPC_ACTION_STOP);
        return -1;
    }

    return 0;
}

static int IPCActionBtDumpStart(const struct rte_mp_msg *msg, const void *peer)
{
    int ret;

    struct rte_mp_msg mp_resp;
    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name) / sizeof(mp_resp.name[0]));
    strlcpy((char *)mp_resp.param, IPC_VALID_RESPONSE, sizeof(mp_resp.param) / sizeof(mp_resp.param[0]));
    mp_resp.len_param = (int)strlen((char *)IPC_VALID_RESPONSE);
    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        uint8_t tout_sec = 5;
        ret = LcoreStateCheckAllWTimeout(LCORE_RUNNING_DONE, tout_sec);
        if (ret != 0) {
            Log().error(ETIMEDOUT, "Workers has not stopped in time (%s sec)", tout_sec);
            exit(1);
        }

        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_STAT_DUMP);
        }
    } else {
        Log().warning(ENOTSUP, "Error (%s): Unable to reply for action %s",
                rte_strerror(rte_errno), IPC_ACTION_BYPASS_TBL_DUMP_START);
        return -1;
    }

    return 0;
}

static int IPCActionBtDumpStop(const struct rte_mp_msg *msg, const void *peer)
{
    int ret;
    struct rte_mp_msg mp_resp;
    memset(&mp_resp, 0, sizeof(mp_resp));
    strlcpy(mp_resp.name, msg->name, sizeof(mp_resp.name) / sizeof(mp_resp.name[0]));
    strlcpy((char *)mp_resp.param, IPC_VALID_RESPONSE, sizeof(mp_resp.param) / sizeof(mp_resp.param[0]));
    mp_resp.len_param = (int)strlen((char *)mp_resp.param);

    ret = rte_mp_reply((struct rte_mp_msg *)&mp_resp, peer);
    if (ret == 0) {
        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_STAT_DUMP_DONE);
        }
    } else {
        Log().warning(ENOTSUP, "Error (%s): Unable to reply for action %s",
                rte_strerror(rte_errno), IPC_ACTION_BYPASS_TBL_DUMP_STOP);
        return -1;
    }

    return 0;
}

static int IPCInit(
        struct action_control *actions,
        struct ctx_ring_conf_list_entry_resource *ring_conf_entries,
        uint16_t ring_conf_entries_cnt)
{
    int ret;
    ret = rte_mp_action_register(IPC_ACTION_ATTACH, IPCActionAttach);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_ATTACH);
        return -rte_errno;
    }

    ret = rte_mp_action_register(IPC_ACTION_DETACH, IPCActionDetach);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_ATTACH);
        return -rte_errno;
    }

    ret = rte_mp_action_register(IPC_ACTION_START, IPCActionPktsStart);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_START);
        return -rte_errno;
    }

    ret = rte_mp_action_register(IPC_ACTION_STOP, IPCActionPktsStop);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_STOP);
        return -rte_errno;
    }

    ret = rte_mp_action_register(IPC_ACTION_BYPASS_TBL_DUMP_START, IPCActionBtDumpStart);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_BYPASS_TBL_DUMP_START);
        return -rte_errno;
    }

    ret = rte_mp_action_register(IPC_ACTION_BYPASS_TBL_DUMP_STOP, IPCActionBtDumpStop);
    if (ret != 0) {
        Log().warning(ENOTSUP, "Error (%s): Unable to register action (%s)",
                rte_strerror(rte_errno), IPC_ACTION_BYPASS_TBL_DUMP_STOP);
        return -rte_errno;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    struct prefilter_args args = {
        .conf_path = NULL,
        .log_lvl = PF_INFO,
    };

    EalInit(&argc, &argv);
    ret = ArgsParse(argc, argv, &args);
    if (ret != 0)
        goto cleanup;

    SignalInit();

    LoggerInit(logger_basic_ops, args.log_lvl);

    //    dev_conf_suricata_ops
    DevConfInit(dev_conf_suricata_ops);
    Log().info("Init done");
    ret = DevConfConfigureBy((void *)args.conf_path);
    if (ret != 0) {
        goto cleanup;
    }
    Log().info("Configure done");

    ret = DevConfCtxResourcesInit();
    if (ret != 0)
        goto cleanup;

    Log().info("CTX resource init done");

    ret = DevConfRingsInit();
    if (ret != 0)
        goto cleanup;

    Log().info("Rings init done");

    ret = DevConfMessagesInit();
    if (ret != 0)
        goto cleanup;

    Log().info("Message init done");

    ret = DevConfSharedConfInit();
    if (ret != 0)
        goto cleanup;

    BypassHashTableSetOps(rte_table_hash_ext_ops);

    ret = PFStatsInit(&ctx.app_stats);
    if (ret != 0)
        goto cleanup;

    ret = DevConfThreadingInit();
    if (ret != 0)
        goto cleanup;

    ret = IPCInit(
            &ctx.status.actions,
            ctx.ring_conf_entries,
            ctx.ring_conf_entries_cnt);
    if (ret != 0)
        goto cleanup;

    ret = LcoreManagerRunWorkers(ctx.app_stats);
    if (ret != 0)
        goto cleanup;

    ret = DevConfStartAll();
    if (ret != 0)
        goto cleanup;

    if (LcoreMainAsWorker != NULL) {
        // the main lcore must work
        Log().info("Running the workload on the main lcore");
        ThreadMain((void *)LcoreMainAsWorker);
    }

cleanup:
    rte_eal_mp_wait_lcore();
    DevConfStopAll();

    PFStatsExitLog(ctx.app_stats);

    for (int i = 0; i < ctx.ring_conf_entries_cnt; i++) {
        if (ctx.ring_conf_entries != NULL) {
            struct ctx_ring_conf_list_entry_resource *mr = &ctx.ring_conf_entries[i];
            for (int j = 0; j < mr->rings_from_pf.ring_arr_len; j++) {
                if (mr->rings_from_pf.ring_arr[j] != NULL) {
                    rte_ring_free(mr->rings_from_pf.ring_arr[j]);
                }
            }

            for (int j = 0; j < mr->rings_to_pf.ring_arr_len; j++) {
                if (mr->rings_to_pf.ring_arr[j] != NULL) {
                    rte_ring_free(mr->rings_to_pf.ring_arr[j]);
                }
            }

            for (int j = 0; j < mr->rings_tasks.ring_arr_len; j++) {
                if (mr->rings_tasks.ring_arr[j] != NULL) {
                    rte_ring_free(mr->rings_tasks.ring_arr[j]);
                }
            }

            for (int j = 0; j < mr->rings_result.ring_arr_len; j++) {
                if (mr->rings_result.ring_arr[j] != NULL) {
                    rte_ring_free(mr->rings_result.ring_arr[j]);
                }
            }

            for (int j = 0; j < mr->mempools_messages.mempool_arr_len; j++) {
                if (mr->mempools_messages.mempool_arr[j] != NULL) {
                    rte_mempool_free(mr->mempools_messages.mempool_arr[j]);
                }
            }
        }
    }

    for (int i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
        struct ctx_lcore_resources *lv = &ctx.lcores_state.lcores_arr[i];
        if (lv == NULL)
            continue;

        BypassHashTableDeinit(&lv->bypass_table);
        if (lv->state != NULL)
            rte_free(lv->state);
    }

    if (ctx.shared_conf != NULL) {
        Log().debug("Freeing the shared configuration");
        rte_memzone_free(ctx.shared_conf);
    }

    PFStatsDeinit(ctx.app_stats);
    DevConfDeinit();
    rte_eal_cleanup();

    return ret;
}