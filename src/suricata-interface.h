/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Interface to the suricata library.
 */

#ifndef __SURICATA_INTERFACE_H__
#define __SURICATA_INTERFACE_H__

#include "suricata.h"
#include "suricata-interface-stream.h"
#include "threadvars.h"


#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration(s). */
typedef struct SuricataCfg SuricataCfg;

/* Used at init and deinit only for now */
typedef struct SuricataCtx {
    /* Configuration object. */
    SuricataCfg *cfg;

    /* Whether the initialization step completed successfully. */
    int init_done;

    /* Whether the post initialization step completed successfully. */
    int post_init_done;

    /* Number of workers that will be created. */
    int n_workers;

    /* Number of workers that are already created. */
    int n_workers_created;

    /* Number of workers that are done processing. */
    int n_workers_done;

    /* Mutex to access the fields. */
    pthread_mutex_t lock;
} SuricataCtx;


/**
 * \brief Create a Suricata context.
 *
 * \param n_workers    Number of packet processing threads that the engine is expected to support.
 * \return SuricataCtx Pointer to the initialized Suricata context.
 */
SuricataCtx *suricata_create_ctx(int n_workers);

/**
 * \brief Register a callback that is invoked for every alert.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_alert_cb(SuricataCtx *ctx, CallbackFuncAlert callback);

/**
 * \brief Register a callback that is invoked for every fileinfo event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_fileinfo_cb(SuricataCtx *ctx, CallbackFuncFileinfo callback);

/**
 * \brief Register a callback that is invoked for every flow.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flow_cb(SuricataCtx *ctx, CallbackFuncFlow callback);

/**
 * \brief Register a callback that is invoked for every FlowSnip event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flowsnip_cb(SuricataCtx *ctx, CallbackFuncFlowSnip callback);

/**
 * \brief Register a callback that is invoked for every HTTP event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_http_cb(SuricataCtx *ctx, CallbackFuncHttp callback);

/**
 * \brief Register a callback that is invoked for every NTA event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_nta_cb(SuricataCtx *ctx, CallbackFuncNta callback);

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
void suricata_register_sig_cb(SuricataCtx *ctx, CallbackFuncSig callback);

/**
 * \brief Register a callback that is invoked every time `suricata_get_stats` is invoked.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_stats_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncStats callback);

/**
 * \brief Retrieve suricata stats.
 */
void suricata_get_stats(void);

/**
 * \brief Register a callback that is invoked for every log message.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_log_cb(SuricataCtx *ctx, CallbackFuncLog callback);

/**
 * \brief Set a configuration option.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param key            The configuration option key.
 * \param val            The configuration option value.
 *
 * \return               1 if set, 0 if not set.
 */
int suricata_config_set(SuricataCtx *ctx, const char *key, const char *val);

/**
 * \brief Load configuration from file.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param config_file    Filename of the yaml configuration to load.
 */
void suricata_config_load(SuricataCtx *ctx, const char *config_file);

/**
 * \brief Enable suricata IPS mode (testing only).
 */
void suricata_enable_ips_mode(void);

/**
 * \brief Initialize a Suricata context.
 *
 * \param ctx            Pointer to SuricataCtx.
 */
void suricata_init(SuricataCtx *ctx);

/**
 * \brief Initialize a Suricata worker.
 *
 * This function is meant to be invoked by a thread in charge of processing packets. The thread
 * is not managed by the library, i.e it needs to be created and destroyed by the user.
 * This function has to be invoked before "suricata_handle_packet" or "suricata_handle_stream".
 *
 * \param ctx       Pointer to the Suricata context.
 * \param interface The interface name this worker is linked to (optional).
 * \return          Pointer to the worker context.
 */
ThreadVars *suricata_initialise_worker_thread(SuricataCtx *ctx, const char *interface);

/**
 * \brief Suricata post initialization tasks.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_post_init(SuricataCtx *ctx);

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
                           uint32_t tenant_id, void *user_ctx);

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
                           void *user_ctx);

/**
 * \brief Reload the detection engine (rule set).
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_engine_reload(SuricataCtx *ctx);

/**
 * \brief Cleanup a Suricata worker.
 *
 * \param ctx Pointer to the Suricata context.
 * \param tv  Pointer to the worker context.
 */
void suricata_deinit_worker_thread(SuricataCtx *ctx, ThreadVars *tv);

/**
 * \brief Shutdown the Suricata engine.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_shutdown(SuricataCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __SURICATA_INTERFACE_H__ */

