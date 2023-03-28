/* Callbacks for various suricata events. */

#include "util-callbacks.h"


/* Callback invoked for each Suricata Alert event. */
void callbackAlert(AlertEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata Fileinfo event. */
void callbackFile(FileinfoEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata HTTP event. */
void callbackHttp(HttpEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each Suricata Flow event. */
void callbackFlow(FlowEvent *event, uint64_t *tenant_uuid, void *user_ctx);
/* Callback invoked for each candidate signature. */
int callbackSig(uint32_t signature_id, uint8_t current_action, uint32_t tenant_id,
                uint64_t *tenant_uuid, void *user_ctx);