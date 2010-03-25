/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __ALERT_DEBUGLOG_H__
#define __ALERT_DEBUGLOG_H__

void TmModuleAlertDebugLogRegister (void);
void TmModuleAlertDebugLogIPv4Register (void);
void TmModuleAlertDebugLogIPv6Register (void);
OutputCtx *AlertDebugLogInitCtx(ConfNode *);

#endif /* __ALERT_DEBUGLOG_H__ */

