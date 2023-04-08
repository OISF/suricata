/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 */

#ifndef __UTIL_CALLBACKS_H__
#define __UTIL_CALLBACKS_H__

#include "util-events.h"

/* Callback functions, one per event. */
typedef void(CallbackFuncAlert)(void *user_ctx, AlertEvent *alert_event);

typedef void(CallbackFuncFileinfo)(void *user_ctx, FileinfoEvent *fileinfo_event);

typedef void(CallbackFuncFlow)(void *user_ctx, FlowEvent *flow_event);

typedef void(CallbackFuncHttp)(void *user_ctx, HttpEvent *http_event);

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
} Callbacks;

#endif /* __UTIL_CALLBACKS_H__ */
