/* Callbacks for various suricata events. */
#include "suricata-interface-events.h"
#include "callbacks.h"

#include <stdio.h>
#include <string.h>


/* Callback invoked for each Suricata Alert event. */
void callbackAlert(AlertEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    char *data = NULL;
    size_t len = 0;
    FILE *eve_fp = (FILE *)user_ctx;

    suricata_alert_to_json(event, &data, &len);

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);

    free((void *)data);
}

/* Callback invoked for each Suricata Fileinfo event. */
void callbackFile(FileinfoEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("Fileinfo!\n");
    if (user_ctx == NULL) {
        return;
    }

    char *data = NULL;
    size_t len = 0;
    FILE *eve_fp = (FILE *)user_ctx;

    suricata_fileinfo_to_json(event, &data, &len);

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);

    free((void *)data);
}

/* Callback invoked for each Suricata HTTP event. */
void callbackHttp(HttpEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    printf("HTTP!\n");
    if (user_ctx == NULL) {
        return;
    }

    char *data = NULL;
    size_t len = 0;
    FILE *eve_fp = (FILE *)user_ctx;

    suricata_http_to_json(event, &data, &len);

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);

    free((void *)data);
}

/* Callback invoked for each NTA event. */
void callbackNta(void *data, size_t len, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    FILE *eve_fp = (FILE *)user_ctx;

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);
}

/* Callback invoked for each Suricata Flow event. */
void callbackFlow(FlowEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    char *data = NULL;
    size_t len = 0;
    FILE *eve_fp = (FILE *)user_ctx;

    suricata_flow_to_json(event, &data, &len);

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);

    free((void *)data);
}

/* Callback invoked for each Suricata FlowSnip event. */
void callbackFlowSnip(FlowSnipEvent *event, uint64_t *tenant_uuid, void *user_ctx) {
    if (user_ctx == NULL) {
        return;
    }

    char *data = NULL;
    size_t len = 0;
    FILE *eve_fp = (FILE *)user_ctx;

    suricata_flowsnip_to_json(event, &data, &len);

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);

    free((void *)data);
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

    /* Write line and append '\n'. */
    fwrite(data, 1, len, eve_fp);
    fwrite("\n", 1, 1, eve_fp);
}

/* Callback invoked for each log message (testing only). */
void callbackLog(int log_level, const char *message) {
    printf("LOG: %s\n", message);
}