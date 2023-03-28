/* Callbacks for various suricata events. */

#include "callbacks.h"

#include <stdio.h>
#include <string.h>


/* Callback invoked for each Suricata Alert event. */
void callbackAlert(AlertEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Alert!, sid %d\n", event->alert.sid);

    if (event->common.app_proto && strcmp(event->common.app_proto, "http") == 0) {
        if (event->app_layer.http && event->app_layer.http->hostname) {
            printf("Alert HTTP hostname %s\n", event->app_layer.http->hostname);
        }
    }
}

/* Callback invoked for each Suricata Fileinfo event. */
void callbackFile(FileinfoEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("File!, name %s\n", event->fileinfo.filename);

    if (event->common.app_proto && strcmp(event->common.app_proto, "http") == 0) {
        if (event->app_layer.http && event->app_layer.http->hostname) {
            printf("Fileinfo HTTP hostname %s\n", event->app_layer.http->hostname);
        }
    }
}

/* Callback invoked for each Suricata HTTP event. */
void callbackHttp(HttpEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Http!, hostname %s\n", event->http.hostname);
}

/* Callback invoked for each Suricata Flow event. */
void callbackFlow(FlowEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Flow!, state %s\n", event->flow.state);
}

/* Callback invoked for each candidate signature. */
int callbackSig(uint32_t signature_id, uint8_t current_action, uint32_t tenant_id,
                uint64_t *tenant_uuid, void *user_ctx) {
    printf("Signature hit!, sid %d action %d\n", signature_id, current_action);

    return 0;
}
