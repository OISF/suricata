/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 */

#ifndef __SURICATA_INTERFACE_H__
#define __SURICATA_INTERFACE_H__

#include "suricata.h"
#include "threadvars.h"

/* Used at init and deinit only for now */
typedef struct SuricataCtx {
    /* Number of worker threads that will be created. */
    int n_workers;

    /* Number of worker threads that are already created. */
    int n_workers_created;

    /* Number of worker threads that are done processing. */
    int n_workers_done;

    /* Callbacks to invoke for each event. */
    Callbacks callbacks;

    /* Mutex to access the fields. */
    pthread_mutex_t lock;
} SuricataCtx;

/**
 * \brief Create a Suricata context.
 *
 * \param n_workers    Number of worker threads that will be allocated.
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
void suricata_register_fileinfo_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFileinfo callback);

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
 * \brief Initialize a Suricata context.
 *
 * \param config      Configuration string.
 */
void suricata_init(const char *config);

/**
 * \brief Create a worker thread.
 *
 * \param ctx Pointer to the Suricata context.
 * \return    Pointer to the worker thread context.
 */
ThreadVars *suricata_create_worker_thread(SuricataCtx *ctx);

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
 * \return                      Error code.
 */
int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, int ignore_pkt_checksum);

/**
 * \brief Destroy a worker thread.
 *
 * \param ctx Pointer to the Suricata context.
 * \param tv  Pointer to the worker thread context.
 */
void suricata_destroy_worker_thread(SuricataCtx *ctx, ThreadVars *tv);

/**
 * \brief Shutdown the Suricata engine.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_shutdown(SuricataCtx *ctx);

#endif /* __SURICATA_INTERFACE_H__ */
