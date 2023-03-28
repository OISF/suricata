/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 */

#ifndef __SURICATA_INTERFACE_H__
#define __SURICATA_INTERFACE_H__

#include "suricata.h"
#include "suricata-interface-stream.h"
#include "threadvars.h"

/* Used at init and deinit only for now */
typedef struct SuricataCtx {
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
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_alert_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncAlert callback);

/**
 * \brief Register a callback that is invoked for every fileinfo event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_fileinfo_cb(SuricataCtx *ctx, void *user_ctx,
                                   CallbackFuncFileinfo callback);

/**
 * \brief Register a callback that is invoked for every flow.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_flow_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFlow callback);

/**
 * \brief Register a callback that is invoked for every HTTP event.
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_http_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncHttp callback);

/**
 * \brief Register a callback that is invoked before a candidate signature is inspected.
 *
 *        Such callback will be able to decide if a signature is relevant or modify its action via
 *        the return value:
 *         * -1: discard
 *         * 0: inspect signature without modify its action
 *         * >0: inspect signature but modify its action first with the returned valued
 *
 * \param ctx            Pointer to SuricataCtx.
 * \param user_ctx       Pointer to a user-defined context object.
 * \param callback       Pointer to a callback function.
 */
void suricata_register_sig_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncSig callback);

/**
 * \brief Initialize a Suricata context.
 *
 * \param config      Configuration string.
 */
void suricata_init(const char *config);

/**
 * \brief Initialize a Suricata worker.
 *
 * This function is meant to be invoked by a thread in charge of processing packets. The thread
 * is not handled by the library, i.e it needs to be created destroyed by the user.
 * This function has to be invoked before "suricata_handle_packet".
 *
 * \param ctx Pointer to the Suricata context.
 * \return    Pointer to the worker context.
 */
ThreadVars *suricata_initialise_worker_thread(SuricataCtx *ctx);

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
 * \return                      Error code.
 */
int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
                           uint32_t len, int ignore_pkt_checksum, uint64_t *tenant_uuid,
                           uint32_t tenant_id);

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
                           uint64_t *tenant_uuid, uint32_t tenant_id);

/**
 * \brief Destroy a worker thread.
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

#endif /* __SURICATA_INTERFACE_H__ */

