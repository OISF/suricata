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
#include "flow-manager.h"
#include "runmode-lib.h"
#include "source-lib.h"

#define SURICATA_PROGNAME "suricata"


/**
 * \brief Utility method to register the callback id into the suricata instance.
 *
 * \param id    Id of the callback to register.
 */
static void setCallbackId(uint32_t id) {
    SCInstance *suri = GetInstance();
    int i = 0;

    while (suri->callback_ids[i]) {
        i++;
    }
    assert(i < MAX_CALLBACKS);

    suri->callback_ids[i] = id;
}

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
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_alert_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncAlert callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.alert.func = callback;
    suri->callbacks.alert.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_ALERT);
}

/**
 * \brief Register a callback that is invoked for every fileinfo event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_fileinfo_cb(SuricataCtx *ctx, void *user_ctx,
                                   CallbackFuncFileinfo callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.fileinfo.func = callback;
    suri->callbacks.fileinfo.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_FILE);
}
/**
 * \brief Register a callback that is invoked for every flow.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flow_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFlow callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.flow.func = callback;
    suri->callbacks.flow.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_FLOW);
}

/**
 * \brief Register a callback that is invoked for every HTTP event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_http_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncHttp callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.http.func = callback;
    suri->callbacks.http.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_TX);
}

/**
 * \brief Register a callback that is invoked for every NTA event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_nta_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncNta callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.nta.func = callback;
    suri->callbacks.nta.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_TX);
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
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_sig_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncSig callback) {
    SCInstance *suri = GetInstance();

    suri->callbacks.sig.func = callback;
    suri->callbacks.sig.user_ctx = user_ctx;
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
 * \return                      Error code.
 */
int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
                           uint32_t len, int ignore_pkt_checksum, uint64_t *tenant_uuid,
                           uint32_t tenant_id) {
    return TmModuleLibHandlePacket(tv, data, datalink, ts, len, ignore_pkt_checksum, tenant_uuid,
                                   tenant_id);
}

/** \brief Feed a single stream segment to the library.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param finfo                 Pointer to the flow information.
 * \param data                  Pointer to the raw packet.
 * \param len                   Packet length.
 * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \return                      Error code.
 */
int suricata_handle_stream(ThreadVars *tv, FlowInfo *finfo, const uint8_t *data, uint32_t len,
                           uint64_t *tenant_uuid, uint32_t tenant_id) {
    return TmModuleLibHandleStream(tv, finfo, data, len, tenant_uuid, tenant_id);
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

    EngineDone(); /* needed only in offlne mode ?. */
    SuricataShutdown();

    /* Cleanup the Suricata configuration. */
    CfgFree(ctx->cfg);
    free(ctx->cfg);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);

    return;
}
