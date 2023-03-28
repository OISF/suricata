/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 */

#ifndef __UTIL_CALLBACKS_H__
#define __UTIL_CALLBACKS_H__

#include "util-events.h"


/* Callback functions, one per event. */
typedef void (CallbackFuncAlert)(
    AlertEvent *alert_event,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncFileinfo)(
    FileinfoEvent *fileinfo_event,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncFlow)(
    FlowEvent *flow_event,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncHttp)(
    HttpEvent *http_event,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncNta)(
    void *data,
    size_t len,
    uint64_t *tenant_uuid,
    void *user_ctx
);

/* Detection callback, invoked before inspecting any signature candidate to remove the signature or
 * modify its action. */
typedef int (CallbackFuncSig)(
    uint32_t signature_id,
    uint8_t current_action,
    uint32_t tenant_id,
    uint64_t *tenant_uuid,
    void *user_ctx
);

/* Callback struct. */
typedef struct {
    struct {
        CallbackFuncAlert *func;
        void *user_ctx;
    } alert;

    struct {
        CallbackFuncFileinfo *func;
        void *user_ctx;
    } fileinfo;

    struct {
        CallbackFuncFlow *func;
        void *user_ctx;
    } flow;

    struct {
        CallbackFuncHttp *func;
        void *user_ctx;
    } http;

    struct {
        CallbackFuncNta *func;
        void *user_ctx;
    } nta;

    struct {
        CallbackFuncSig *func;
        void *user_ctx;
    } sig;
} Callbacks;

#endif /* __UTIL_CALLBACKS_H__ */
