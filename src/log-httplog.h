/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __LOG_HTTPLOG_H__
#define __LOG_HTTPLOG_H__

void TmModuleLogHttplogRegister (void);
void TmModuleLogHttplogIPv4Register (void);
void TmModuleLogHttplogIPv6Register (void);
LogFileCtx *LogHttplogInitCtx(char *);

#endif /* __LOG_HTTPLOG_H__ */

