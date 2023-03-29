/* Callbacks for various suricata events. */

#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

#include "util-callbacks.h"


/* Callback invoked for each Suricata Alert event. */
void callbackAlert(AlertEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata Fileinfo event. */
void callbackFile(FileinfoEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata HTTP event. */
void callbackHttp(HttpEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata Flow event. */
void callbackFlow(FlowEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata FlowSnip event. */
void callbackFlowSnip(FlowSnipEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each NTA event. */
void callbackNta(void *data, size_t len, const char *event_type, uint64_t *tenant_uuid,
                 void *user_ctx);
/* Callback invoked for each Suricata PreventAction event. */
void callbackPreventAction(PreventActionEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each signature that fails to load. */
void callbackSigFailedLoading(const char *signature, const char *signature_file, int line_number,
                              void *user_ctx);
/* Callback invoked for each candidate signature. */
int callbackSigCandidate(uint32_t signature_id, uint8_t current_action, uint32_t tenant_id,
                         uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each stats event. */
void callbackStats(void *data, size_t len, void *user_ctx);
/* Callback invoked for each log message (testing only). */
void callbackLog(int log_level, const char *message);

#endif /* __CALLBACKS_H__ */
