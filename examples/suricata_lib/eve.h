/* EVE output module. */

#ifndef __EVE_H__
#define __EVE_H__

#include "util-callbacks.h"

#include <stdio.h>


/* Log an Alert event. */
void logAlert(FILE *fp, AlertEvent *event);
/* Log an HTTP event. */
void logHttp(FILE *fp, HttpEvent *event);
/* Log a Fileinfo event. */
void logFileinfo(FILE *fp, FileinfoEvent *event);
/* Log a FlowSnip event. */
void logFlowSnip(FILE *fp, FlowSnipEvent *event);
/* Log an NTA event. */
void logNta(FILE *fp, void *data, size_t len);

#endif /* __EVE_H__ */
