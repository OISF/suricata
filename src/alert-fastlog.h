/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "tm-modules.h"
#ifndef __ALERT_FASTLOG_H__
#define __ALERT_FASTLOG_H__

void TmModuleAlertFastlogRegister (void);
void TmModuleAlertFastlogIPv4Register (void);
void TmModuleAlertFastlogIPv6Register (void);
LogFileCtx *AlertFastlogInitCtx(char *);

#endif /* __ALERT_FASTLOG_H__ */

