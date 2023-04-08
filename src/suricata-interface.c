/*
 *  Interface to the suricata library.
 */

/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Interface to the suricata library.
 */

#include "suricata-interface.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "runmode-lib.h"
#include "source-lib.h"
#include "util-mem.h"

/**
 * \brief Utility method to split the config string into the argc/argv format.
 *
 * \param config      Configuration string.
 * \param argv        Parameter that will hold the command line options.
 * \return int        Number of command line options.
 */
static char **split_config_string(const char *config, int *argc)
{
    char **argv = NULL;
    int i = 2;

    /* Initialize to 2 to take account of first and last options added separately. */
    *argc = 2;
    char *copy = SCStrdup(config);
    if (copy == NULL) {
        fprintf(stderr, "Failed to allocate memory for suricata config");
        exit(EXIT_FAILURE);
    }

    char *xsaveptr = NULL;
    char *key = strtok_r(copy, ";", &xsaveptr);
    while (key != NULL) {
        /* If the option contains a value we increase argc by 2. */
        strstr(key, "=") != NULL ? *argc += 2 : (*argc)++;
        key = strtok_r(NULL, ";", &xsaveptr);
    }
    free(copy);

    /* Another iteration to store the values in argv. */
    copy = SCStrdup(config);
    if (copy == NULL) {
        fprintf(stderr, "Failed to allocate memory for suricata config");
        exit(EXIT_FAILURE);
    }

    argv = calloc(*argc + 1, sizeof(char *));
    argv[0] = (char *)"suricata";
    argv[1] = (char *)"--lib";
    xsaveptr = NULL;
    key = strtok_r(copy, ";", &xsaveptr);
    while (key != NULL) {
        const char *tmp = strstr(key, "=");
        if (tmp != NULL) {
            argv[i++] = SCStrndup(key, tmp - key);

            char *val = SCStrdup(++tmp);
            if (val == NULL) {
                fprintf(stderr, "Failed to allocate memory for suricata config");
                exit(EXIT_FAILURE);
            }
            argv[i++] = val;
        } else {
            char *val = SCStrdup(key);
            if (val == NULL) {
                fprintf(stderr, "Failed to allocate memory for suricata config");
                exit(EXIT_FAILURE);
            }

            argv[i++] = val;
        }

        key = strtok_r(NULL, ";", &xsaveptr);
    }
    free(copy);

    return argv;
}

/**
 * \brief Utility method to register the callback id into the suricata instance.
 *
 * \param id    Id of the callback to register.
 */
static void setCallbackId(uint32_t id)
{
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
 * \param n_workers    Number of worker threads that will be allocated.
 * \return SuricataCtx Pointer to the initialized Suricata context.
 */
SuricataCtx *suricata_create_ctx(int n_workers)
{
    /* Create the SuricataCtx */
    if (n_workers == 0) {
        fprintf(stderr, "The number of suricata worker threads must be > 0");
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
void suricata_register_alert_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncAlert callback)
{
    ctx->callbacks.alert.func = callback;
    ctx->callbacks.alert.user_ctx = user_ctx;

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
void suricata_register_fileinfo_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFileinfo callback)
{
    ctx->callbacks.fileinfo.func = callback;
    ctx->callbacks.fileinfo.user_ctx = user_ctx;

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
void suricata_register_flow_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFlow callback)
{
    ctx->callbacks.flow.func = callback;
    ctx->callbacks.flow.user_ctx = user_ctx;

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
void suricata_register_http_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncHttp callback)
{
    ctx->callbacks.http.func = callback;
    ctx->callbacks.http.user_ctx = user_ctx;

    /* Set the callback id into the suricata array to later register the output module. */
    setCallbackId(LOGGER_CALLBACK_TX);
}

/**
 * \brief Initialize a Suricata context.
 *
 * \param config      Configuration string.
 */
void suricata_init(const char *config)
{
    /* Convert the config string into the argc/argv format */
    int i = 2;
    int argc = 0;
    char **argv = split_config_string(config, &argc);

    SuricataInit(argc, argv);

    while (i < argc) {
        free(argv[i]);
        i++;
    }
    free(argv);
}

/**
 * \brief Create a worker thread.
 *
 * \param ctx Pointer to the Suricata context.
 * \return    Pointer to the worker thread context.
 */
ThreadVars *suricata_create_worker_thread(SuricataCtx *ctx)
{
    pthread_mutex_lock(&ctx->lock);

    if (ctx->n_workers_created == ctx->n_workers) {
        fprintf(stderr, "Maximum number of workers thread already allocated");
        return NULL;
    }

    ThreadVars *tv = RunModeCreateWorker();
    tv->callbacks = &ctx->callbacks;
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
void suricata_post_init(SuricataCtx *ctx)
{
    /* Wait till all the worker threads have been created. */
    while (ctx->n_workers_created < ctx->n_workers) {
        usleep(100);
    }

    SuricataPostInit();
    return;
}

/**
 * \brief Destroy a worker thread.
 *
 * \param ctx Pointer to the Suricata context.
 * \param tv  Pointer to the worker thread context.
 */
void suricata_destroy_worker_thread(SuricataCtx *ctx, ThreadVars *tv)
{
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
 * \return                      Error code.
 */
int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, int ignore_pkt_checksum)
{
    return TmModuleLibHandlePacket(tv, data, datalink, ts, len, ignore_pkt_checksum);
}

/**
 * \brief Shutdown the library.
 *
 * \param ctx Pointer to the Suricata context.
 */
void suricata_shutdown(SuricataCtx *ctx)
{
    /* Wait till all the worker threads are done */
    while (ctx->n_workers_done != ctx->n_workers) {
        usleep(10 * 1000);
    }

    EngineDone(); /* needed only in offlne mode ?. */
    SuricataShutdown();

    pthread_mutex_destroy(&ctx->lock);
    free(ctx);

    return;
}
