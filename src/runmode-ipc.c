//
// Created by Danny Browning on 10/6/18.
//

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-ipc.h"
#include "output.h"

#include "detect-engine.h"
#include "source-pcap-file.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "util-runmodes.h"

static const char *default_mode = NULL;

const char *RunModeIpcGetDefaultMode(void)
{
    return default_mode;
}

void RunModeIpcRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_IPC, "single",
                              "Single threaded ipc mode",
                              RunModeIpcSingle);
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_IPC, "autofp",
                              "Multi threaded ipc mode.  Packets from "
                              "each flow are assigned to a single detect thread.",
                              RunModeIpcAutoFp);
    RunModeRegisterNewRunMode(RUNMODE_IPC, "workers",
                              "Ipc workers mode, each thread does all"
                              "tasks from acquisition to logging",
                              RunModeIpcWorkers);
    return;
}

static void IpcDerefConfig(void *conf)
{
    IpcConfig *ipc = (IpcConfig *)conf;
    if (SC_ATOMIC_SUB(ipc->ref, 1) == 1) {
        for(int i = 0; i < ipc->nb_servers; i++) {
            SCFree(ipc->servers[i]);
        }
        SCFree(ipc->servers);
        SCFree(ipc);
    }
}

static int IpcGetThreadsCount(void *conf)
{
    IpcConfig *ipc = (IpcConfig *)conf;
    return ipc->nb_servers;
}

static void *ParseIpcConfig(const char *servers)
{
    if(unlikely(servers == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "Ipc servers was null");
        return NULL;
    }
    SCLogInfo("Ipc using servers %s", servers);

    IpcConfig *conf = SCMalloc(sizeof(IpcConfig));
    if(unlikely(conf == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        return NULL;
    }
    memset(conf, 0, sizeof(IpcConfig));

    char delim[] = ",";
    char *tok_servers[1000];

    char *mod_servers = SCStrdup(servers);
    char *saveptr = NULL;
    char *token = strtok_r(mod_servers, delim, &saveptr);
    conf->nb_servers = 0;
    while (token != NULL) {
        if(conf->nb_servers == 1000) {
            SCLogWarning(SC_ERR_RUNMODE, "More than 1000 servers passed to IPC Runmode, using first 1000");
            break;
        }
        tok_servers[conf->nb_servers] = token;
        conf->nb_servers += 1;
        token = strtok_r(NULL, delim, &saveptr);
    }

    SCLogInfo("Connecting %d servers", conf->nb_servers);

    conf->servers = SCMalloc(sizeof(char*) * conf->nb_servers);
    if(unlikely(conf->servers == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        return NULL;
    }

    for(int server = 0; server < conf->nb_servers; server++) {
        conf->servers[server] = SCStrdup(tok_servers[server]);
        if(unlikely(conf->servers[server] == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
            return NULL;
        }
    }

    conf->allocation_batch = 100;
    if(ConfGetInt("ipc.allocation-batch", &conf->allocation_batch) == 0) {
        SCLogInfo("No ipc.allocation-batch parameters, defaulting to 100");
    }

    conf->DerefFunc = IpcDerefConfig;

    return conf;
}

/**
 * \brief RunModeIpcAutoFp set up the following thread packet handlers:
 *        - Receive thread (from ipc server)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu.
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeIpcAutoFp(void)
{
    SCEnter();

    const char *server = NULL;
    if (ConfGet("ipc.server", &server) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving ipc.server from Conf");
        exit(EXIT_FAILURE);
    }

    int live_mode = 1;
    int conf_live_mode = 0;
    if (ConfGetBool("ipc.live", &conf_live_mode) == 1) {
        live_mode = conf_live_mode;
    } else {
        SCLogInfo("ipc.live not set in config, defaulting to live mode");
    }

    RunModeInitialize();

    if (live_mode) {
        SCLogInfo("IPC using live mode");
        TimeModeSetLive();
    } else {
        SCLogInfo("IPC using offline mode");
        TimeModeSetOffline();
    }

    int ret = RunModeSetLiveCaptureSingle(ParseIpcConfig,
                                      IpcGetThreadsCount,
                                      "ReceiveIpc",
                                      "DecodeIpc",
                                      thread_name_single,
                                      server);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIpcAutoFp initialised");

    return 0;
}

/**
 * \brief Single thread version of the Ipc runmode.
 */
int RunModeIpcSingle(void)
{
    SCEnter();

    const char *server = NULL;
    if (ConfGet("ipc.server", &server) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving ipc.server from Conf");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();

    TimeModeSetOffline();

    int ret = RunModeSetLiveCaptureAutoFp(ParseIpcConfig,
                                          IpcGetThreadsCount,
                                          "ReceiveIpc",
                                          "DecodeIpc",
                                          thread_name_autofp,
                                          server);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIpcSingle initialised");

    return 0;
}

/**
 * \brief Workers version of the Ipc runmode.
 */
int RunModeIpcWorkers(void)
{
    SCEnter();

    int ret;

    RunModeInitialize();

    TimeModeSetOffline();

    const char *server = NULL;
    if (ConfGet("ipc.server", &server) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving ipc.server from Conf");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureWorkers(ParseIpcConfig,
                                       IpcGetThreadsCount,
                                       "ReceiveIpc",
                                       "DecodeIpc",
                                       thread_name_workers,
                                       server);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIpcWorkers initialised");

    return ret;
}