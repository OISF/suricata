/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __ALERT_DEBUGLOG_H__
#define __ALERT_DEBUGLOG_H__

void TmModuleAlertDebuglogRegister (void);
void TmModuleAlertDebuglogIPv4Register (void);
void TmModuleAlertDebuglogIPv6Register (void);
LogFileCtx *AlertDebuglogInitCtx(char *);

#endif /* __ALERT_DEBUGLOG_H__ */

