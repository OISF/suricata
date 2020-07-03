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

    return;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeIpcSingle(void)
{
    const char *server = NULL;
    char tname[TM_THREAD_NAME_MAX];

    if (ConfGet("ipc.server", &server) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving ipc.server from Conf");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();
    TimeModeSetOffline();

    snprintf(tname, sizeof(tname), "%s#01", thread_name_single);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        SCLogError(SC_ERR_RUNMODE, "threading setup failed");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveIpc");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName failed for ReceiveIpc");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, server);

    tm_module = TmModuleGetByName("DecodeIpc");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName DecodePcap failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

#ifndef AFLFUZZ_PCAP_RUNMODE
    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }
#else
    /* in afl mode we don't spawn a new thread, but run the pipeline
     * in the main thread */
    tv->tm_func(tv);
    int afl_runmode_exit_immediately = 0;
    (void)ConfGetBool("afl.exit_after_pcap", &afl_runmode_exit_immediately);
    if (afl_runmode_exit_immediately) {
        SCLogNotice("exit because of afl-runmode-exit-after-pcap commandline option");
        exit(EXIT_SUCCESS);
    }
#endif

    return 0;
}

static void IpcDerefConfig(void *conf)
{
    IpcConfig *ipc = (IpcConfig *)conf;
    if (SC_ATOMIC_SUB(ipc->ref, 1) == 1) {
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
    SCLogDebug("Ipc using servers %s", servers);

    IpcConfig *conf = SCMalloc(sizeof(IpcConfig));

    char delim[] = ",";

    // looping the list of servers twice because we're at startup and it's easier than using a list
    char * token = strtok(servers, delim);
    conf->nb_servers = 0;
    while (token != NULL) {
        conf->nb_servers += 1;
        token = strtok(servers, delim);
    }

    SCLogDebug("Connecting %d servers", conf->nb_servers);

    conf->servers = SCMalloc(sizeof(char*) * conf->nb_servers);
    if(unlikely(conf->servers == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
    }

    int server = 0;
    token = strtok(servers, delim);
    while (token != NULL) {
        conf->servers[server] = token;
        server += 1;
        token = strtok(servers, delim);
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
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    uint16_t cpu = 0;
    char *queues = NULL;
    uint16_t thread;

    const char *server = NULL;
    if (ConfGet("ipc.server", &server) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving ipc.server from Conf");
        exit(EXIT_FAILURE);
    }

    int ret = RunModeSetLiveCaptureAutoFp(ParseIpcConfig,
                                      IpcGetThreadsCount,
                                      "ReceivePfring",
                                      "DecodePfring",
                                      thread_name_autofp,
                                      server);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIpcAutoFp initialised");

    return 0;
}