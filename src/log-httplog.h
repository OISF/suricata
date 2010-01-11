/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __LOG_HTTPLOG_H__
#define __LOG_HTTPLOG_H__

void TmModuleLogHttpLogRegister (void);
void TmModuleLogHttpLogIPv4Register (void);
void TmModuleLogHttpLogIPv6Register (void);
LogFileCtx *LogHttpLogInitCtx(ConfNode *);

#endif /* __LOG_HTTPLOG_H__ */

