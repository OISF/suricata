/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "tm-modules.h"
#ifndef __ALERT_FASTLOG_H__
#define __ALERT_FASTLOG_H__

void TmModuleAlertFastLogRegister (void);
void TmModuleAlertFastLogIPv4Register (void);
void TmModuleAlertFastLogIPv6Register (void);
OutputCtx *AlertFastLogInitCtx(ConfNode *);

#endif /* __ALERT_FASTLOG_H__ */

