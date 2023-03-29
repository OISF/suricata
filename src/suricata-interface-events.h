/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  API to convert events to JSON.
 *
 *  Notice: all these methods transfer ownership of the generated JSON string to the caller. It is
 *          up to the caller to free the received string.
 */

#ifndef __SURICATA_INTERFACE_EVENTS_H__
#define __SURICATA_INTERFACE_EVENTS_H__

#include "suricata-common.h"
#include "util-events.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Convert an Alert event to JSON. */
void suricata_alert_to_json(AlertEvent *event, char **data, size_t *len);

/* Convert a Fileinfo event to JSON. */
void suricata_fileinfo_to_json(FileinfoEvent *event, char **data, size_t *len);

/* Convert a Flow event to JSON. */
void suricata_flow_to_json(FlowEvent *event, char **data, size_t *len);

/* Convert a FlowSnip event to JSON. */
void suricata_flowsnip_to_json(FlowSnipEvent *event, char **data, size_t *len);

/* Convert a HTTP event to JSON. */
void suricata_http_to_json(HttpEvent *event, char **data, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* __SURICATA_INTERFACE_EVENTS_H__ */
