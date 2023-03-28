/* Callbacks for various suricata events. */

#include "callbacks.h"
#include "eve.h"

#include <stdio.h>
#include <string.h>


/* Callback invoked for each Suricata Alert event. */
void callbackAlert(AlertEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logAlert(eve_fp, event);
}

/* Callback invoked for each Suricata Fileinfo event. */
void callbackFile(FileinfoEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Fileinfo!\n");
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logFileinfo(eve_fp, event);
}

/* Callback invoked for each Suricata HTTP event. */
void callbackHttp(HttpEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("HTTP!\n");
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logHttp(eve_fp, event);
}

/* Callback invoked for each NTA event. */
void callbackNta(void *data, size_t len, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logNta(eve_fp, data, len);
}

/* Callback invoked for each Suricata Flow event. */
void callbackFlow(FlowEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Flow!, state %s\n", event->flow.state);

}

/* Callback invoked for each Suricata FlowSnip event. */
void callbackFlowSnip(FlowSnipEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logFlowSnip(eve_fp, event);
}

/* Callback invoked for each candidate signature. */
int callbackSig(uint32_t signature_id, uint8_t current_action, uint32_t tenant_id,
                uint64_t *tenant_uuid, void *user_ctx) {
    printf("Signature hit!, sid %d action %d\n", signature_id, current_action);

    return 0;
}

/* Callback invoked for each stats event. */
void callbackStats(void *data, size_t len, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;
    logNta(eve_fp, data, len);
}

/* Callback invoked for each log message (testing only). */
void callbackLog(int log_level, int error_code, const char *message) {
    printf("LOG: %s\n", message);
}