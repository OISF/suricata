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

typedef void (CallbackFuncFlowSnip)(
    FlowSnipEvent *flowsnip_event,
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
    const char *event_type,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncSigFailedLoading)(
    const char *signature,
    const char *signature_file,
    int line_number,
    void *user_ctx
);

typedef struct CallbackSigFailedLoading {
    CallbackFuncSigFailedLoading *func;
    void *user_ctx;
} CallbackSigFailedLoading;

/* Detection callback, invoked before inspecting any signature candidate to remove the signature or
 * modify its action. */
typedef int (CallbackFuncSigCandidate)(
    uint32_t signature_id,
    uint8_t current_action,
    uint32_t tenant_id,
    uint64_t *tenant_uuid,
    void *user_ctx
);

typedef void (CallbackFuncStats)(
    void *data,
    size_t len,
    void *user_ctx
);

typedef void (CallbackFuncLog)(
    int log_level, /* value corresponding to a SCLogLevel enum */
    const char *message
);

typedef void (CallbackFuncPreventAction)(
    PreventActionEvent *prevent_action_event,
    uint64_t *tenant_uuid,
    void *user_ctx
);

/* Callback struct. */
typedef struct {
    CallbackFuncAlert *alert;
    CallbackFuncFileinfo *fileinfo;
    CallbackFuncFlow *flow;
    CallbackFuncFlowSnip *flowsnip;
    CallbackFuncHttp *http;
    CallbackFuncNta *nta;
    CallbackSigFailedLoading sig_failed_loading;
    CallbackFuncSigCandidate *sig_candidate;
    CallbackFuncLog *log;
    CallbackFuncPreventAction *prevent_action;
} Callbacks;

#endif /* __UTIL_CALLBACKS_H__ */
