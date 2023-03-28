/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Interface to the suricata library.
 */

#include "suricata-interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "conf-struct-loader.h"
#include "counters.h"
#include "output-callback-stats.h"
#include "flow-manager.h"
#include "runmode-lib.h"
#include "source-lib.h"

#define SURICATA_PROGNAME "suricata"


/**
 * \brief Create a Suricata context.
 *
 * \param n_workers    Number of packet processing threads that the engine is expected to support.
 * \return SuricataCtx Pointer to the initialized Suricata context.
 */
SuricataCtx *suricata_create_ctx(int n_workers) {
    /* Create the SuricataCtx */
    if (n_workers == 0) {
        fprintf(stderr, "The number of suricata workers must be > 0");
        exit(EXIT_FAILURE);
    }

    SuricataCtx *ctx = calloc(1, sizeof(SuricataCtx));
    if (ctx == NULL) {
        fprintf(stderr, "SuricataCtx creation failed");
        exit(EXIT_FAILURE);
    }

    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        fprintf(stderr, "SuricataCtx mutex creation failed");
        exit(EXIT_FAILURE);
    }

    ctx->n_workers = n_workers;

    /* Retrieve default configuration. */
    ctx->cfg = calloc(1, sizeof(SuricataCfg));
    if (ctx->cfg == NULL) {
        fprintf(stderr, "SuricataCfg creation failed");
        exit(EXIT_FAILURE);
    }
    *ctx->cfg = CfgGetDefault();

    /* Setup the inner suricata instance. */
    SuricataPreInit("suricata");

    return ctx;
}

/**
 * \brief Register a callback that is invoked for every alert.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_alert_cb(SuricataCtx *ctx, CallbackFuncAlert callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.alert = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.alert.enabled", "yes");
}

/**
 * \brief Register a callback that is invoked for every fileinfo event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_fileinfo_cb(SuricataCtx *ctx, CallbackFuncFileinfo callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.fileinfo = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.fileinfo.enabled", "yes");
}
/**
 * \brief Register a callback that is invoked for every flow.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flow_cb(SuricataCtx *ctx, CallbackFuncFlow callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.flow = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.flow.enabled", "yes");
}

/**
 * \brief Register a callback that is invoked for every FlowSnip event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flowsnip_cb(SuricataCtx *ctx, CallbackFuncFlowSnip callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.flowsnip = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.flow-snip.enabled", "yes");
}

/**
 * \brief Register a callback that is invoked for every HTTP event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_http_cb(SuricataCtx *ctx, CallbackFuncHttp callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.http = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.http.enabled", "yes");
}

/**
 * \brief Register a callback that is invoked for every NTA event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_nta_cb(SuricataCtx *ctx, CallbackFuncNta callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.nta = callback;

    /* Enable callback in the config. */
    CfgSet(ctx->cfg, "outputs.callback.nta.enabled", "yes");
}

/**
 * \brief Register a callback that is invoked before a candidate signature is inspected.
 *
 *        Such callback will be able to decide if a signature is relevant or modify its action via
 *        the return value:
 *         * -1: discard
 *         * 0: inspect signature without modifying its action
 *         * >0: inspect signature but modify its action first with the returned value
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_sig_cb(SuricataCtx *ctx, CallbackFuncSig callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.sig = callback;
}

/**
 * \brief Register a callback that is invoked every time `suricata_get_stats` is invoked.
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_stats_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncStats callback) {
    /* Enable stats in the config and initialize callback module. */
    CfgSet(ctx->cfg, "stats.enabled", "yes");
    CallbackStatsLogInit(user_ctx, callback);
}

/**
 * \brief Retrieve suricata stats.
 */
void suricata_get_stats(void) {
    StatsPoll();
}


/**
 * \brief Register a callback that is invoked for every log message.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_log_cb(SuricataCtx *ctx, CallbackFuncLog callback) {
    SCInstance *suri = GetInstance();
    suri->callbacks.log = callback;

    /* Enable callback in the config. Notice the logging id is hard-coded but it should be fine
     * since suricata right now has only 3 output modules for logging (console, file, syslog) */
    CfgSet(ctx->cfg, "logging.outputs.3.callback.enabled", "yes");
}

/**
 * \brief Set a configuration option.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param key            The configuration option key.
 * \param val            The configuration option value.
 *
 * \return               1 if set, 0 if not set.
 */
int suricata_config_set(SuricataCtx *ctx, const char *key, const char *val) {
    return CfgSet(ctx->cfg, key, val);
}

/**
 * \brief Load configuration from file.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param config_file    ilename of the yaml configuration to load.
 */
void suricata_config_load(SuricataCtx *ctx, const char *config_file) {
    if (config_file && CfgLoadYaml(config_file, ctx->cfg) != 0) {
        /* Loading the configuration from Yaml failed. */
        fprintf(stderr, "Failed loading config file: %s", config_file);
        exit(EXIT_FAILURE);
    }
}

/**
 * \brief Initialize a Suricata context.
 *
 * \param ctx            Pointer to SuricataCtx.
 */
void suricata_init(SuricataCtx *ctx) {
    /* Set runmode and config in the suricata instance. */
    SCInstance *suri = GetInstance();
    suri->run_mode = RUNMODE_LIB;
    suri->set_logdir = true;
    suri->cfg = ctx->cfg;

    /* If we registered at least one callback, force enabling the callback output module. */
    int enabled = 0;
    if (suri->callbacks.alert != NULL || suri->callbacks.fileinfo != NULL ||
        suri->callbacks.flow != NULL || suri->callbacks.http != NULL ||
        suri->callbacks.nta != NULL) {
        enabled = 1;
    }

    if (enabled) {
        CfgSet(ctx->cfg, "outputs.callback.enabled", "yes");
    }

    /* Invoke engine initialization. */
    SuricataInit(SURICATA_PROGNAME);
}

/**
 * \brief Initialize a Suricata worker.
 *
 * This function is meant to be invoked by a thread in charge of processing packets. The thread
 * is not managed by the library, i.e it needs to be created and destroyed by the user.
 * This function has to be invoked before "suricata_handle_packet" or "suricata_handle_stream".
 *
 * \param ctx Pointer to the Suricata context.
 * \return    Pointer to the worker context.
 */
ThreadVars *suricata_initialise_worker_thread(SuricataCtx *ctx) {
    pthread_mutex_lock(&ctx->lock);

    if (ctx->n_workers_created == ctx->n_workers) {
        fprintf(stderr, "Maximum number of workers thread already allocated");
        return NULL;
    }

    ThreadVars *tv = RunModeCreateWorker();
    ctx->n_workers_created++;
    pthread_mutex_unlock(&ctx->lock);

    RunModeSpawnWorker(tv);
    return tv;
}

/**
 * \brief Suricata post initialization tasks.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_post_init(SuricataCtx *ctx) {
    /* Wait till all the workers have been created. */
    while (ctx->n_workers_created < ctx->n_workers) {
        usleep(100);
    }

    SuricataPostInit();
    return;
}

/**
 * \brief Cleanup a Suricata worker.
 *
 * \param ctx Pointer to the Suricata context.
 * \param tv  Pointer to the worker context.
 */
void suricata_deinit_worker_thread(SuricataCtx *ctx, ThreadVars *tv) {
    pthread_mutex_lock(&ctx->lock);
    ctx->n_workers_done++;
    pthread_mutex_unlock(&ctx->lock);

    RunModeDestroyWorker(tv);
    return;
}


/**
 * \brief Feed a packet to the library.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the raw packet.
 * \param datalink              Datalink type.
 * \param ts                    Timeval structure.
 * \param len                   Packet length.
 * \param ignore_pkt_checksum   Boolean indicating if we should ignore the packet checksum.
 * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param user_ctx              Pointer to a user-defined context object.
 * \return                      Error code.
 */
int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
                           uint32_t len, int ignore_pkt_checksum, uint64_t *tenant_uuid,
                           uint32_t tenant_id, void *user_ctx) {
    return TmModuleLibHandlePacket(tv, data, datalink, ts, len, ignore_pkt_checksum, tenant_uuid,
                                   tenant_id, user_ctx);
}

/** \brief Feed a single stream segment to the library.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param finfo                 Pointer to the flow information.
 * \param data                  Pointer to the raw packet.
 * \param len                   Packet length.
 * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param user_ctx              Pointer to a user-defined context object.
 * \return                      Error code.
 */
int suricata_handle_stream(ThreadVars *tv, FlowStreamInfo *finfo, const uint8_t *data,
                           uint32_t len, uint64_t *tenant_uuid, uint32_t tenant_id,
                           void *user_ctx) {
    return TmModuleLibHandleStream(tv, finfo, data, len, tenant_uuid, tenant_id, user_ctx);
}

/**
 * \brief Shutdown the library.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_shutdown(SuricataCtx *ctx) {
    /* Wait till all the workers are done */
    while(ctx->n_workers_done != ctx->n_workers) {
        usleep(10 * 1000);
    }

    /* Retrieve stats one last time. */
    suricata_get_stats();

    EngineDone(); /* needed only in offlne mode ?. */
    SuricataShutdown();

    /* Cleanup the Suricata configuration. */
    CfgFree(ctx->cfg);
    free(ctx->cfg);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);

    return;
}
