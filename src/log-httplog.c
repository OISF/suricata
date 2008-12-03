/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* httplog
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "util-print.h"
#include "util-unittest.h"

int LogHttplog (ThreadVars *, Packet *, void *, PacketQueue *);
int LogHttplogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
int LogHttplogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
int LogHttplogThreadInit(ThreadVars *, void **);
int LogHttplogThreadDeinit(ThreadVars *, void *);
void LogHttplogExitPrintStats(ThreadVars *, void *);

void TmModuleLogHttplogRegister (void) {
    tmm_modules[TMM_LOGHTTPLOG].name = "LogHttplog";
    tmm_modules[TMM_LOGHTTPLOG].Init = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG].Func = LogHttplog;
    tmm_modules[TMM_LOGHTTPLOG].ExitPrintStats = LogHttplogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG].Deinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG].RegisterTests = NULL;
}

void TmModuleLogHttplogIPv4Register (void) {
    tmm_modules[TMM_LOGHTTPLOG4].name = "LogHttplogIPv4";
    tmm_modules[TMM_LOGHTTPLOG4].Init = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG4].Func = LogHttplogIPv4;
    tmm_modules[TMM_LOGHTTPLOG4].Deinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG4].RegisterTests = NULL;
}

void TmModuleLogHttplogIPv6Register (void) {
    tmm_modules[TMM_LOGHTTPLOG6].name = "LogHttplogIPv6";
    tmm_modules[TMM_LOGHTTPLOG6].Init = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG6].Func = LogHttplogIPv6;
    tmm_modules[TMM_LOGHTTPLOG6].Deinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG6].RegisterTests = NULL;
}

typedef struct _LogHttplogThread {
    FILE *fp;
    u_int32_t uri_cnt;
} LogHttplogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    u_int32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (u_int32_t) ts->tv_usec);
}

int LogHttplogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    int i;
    char timebuf[64];

    /* XXX add a better check for this */
    if (p->http_uri.cnt == 0)
        return 0;

    PktVar *pv_hn = PktVarGet(p, "http_host");
    PktVar *pv_ua = PktVarGet(p, "http_ua");

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[16], dstip[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    for (i = 0; i < p->http_uri.cnt; i++) {
        /* time */
        fprintf(aft->fp, "%s ", timebuf);
        /* hostname */
        if (pv_hn != NULL) PrintRawUriFp(aft->fp, pv_hn->value, pv_hn->value_len);
        else fprintf(aft->fp, "<hostname unknown>");
        fprintf(aft->fp, " [**] ");
        /* uri */
        PrintRawUriFp(aft->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->fp, " [**] ");
        /* user agent */
        if (pv_ua != NULL) PrintRawUriFp(aft->fp, pv_ua->value, pv_ua->value_len);
        else fprintf(aft->fp, "<useragent unknown>");
        /* ip/tcp header info */
        fprintf(aft->fp, " [**] %s:%u -> %s:%u\n", srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->fp);

    aft->uri_cnt += p->http_uri.cnt;
    return 0;
}

int LogHttplogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    int i;
    char timebuf[64];

    /* XXX add a better check for this */
    if (p->http_uri.cnt == 0)
        return 0;

    PktVar *pv_hn = PktVarGet(p, "http_host");
    PktVar *pv_ua = PktVarGet(p, "http_ua");

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

    for (i = 0; i < p->http_uri.cnt; i++) {
        /* time */
        fprintf(aft->fp, "%s ", timebuf);
        /* hostname */
        if (pv_hn != NULL) PrintRawUriFp(aft->fp, pv_hn->value, pv_hn->value_len);
        else fprintf(aft->fp, "<hostname unknown>");
        fprintf(aft->fp, " [**] ");
        /* uri */
        PrintRawUriFp(aft->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->fp, " [**] ");
        /* user agent */
        if (pv_ua != NULL) PrintRawUriFp(aft->fp, pv_ua->value, pv_ua->value_len);
        else fprintf(aft->fp, "<useragent unknown>");
        /* ip/tcp header info */
        fprintf(aft->fp, " [**] %s:%u -> %s:%u\n", srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->fp);

    aft->uri_cnt += p->http_uri.cnt;
    return 0;
}

int LogHttplog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (!(PKT_IS_TCP(p)))
        return 0;

    if (PKT_IS_IPV4(p)) {
        return LogHttplogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return LogHttplogIPv6(tv, p, data, pq);
    }

    return 0;
}

int LogHttplogThreadInit(ThreadVars *t, void **data)
{
    LogHttplogThread *aft = malloc(sizeof(LogHttplogThread));
    if (aft == NULL) {
        return -1;
    }
    memset(aft, 0, sizeof(LogHttplogThread));

    /* XXX */
    aft->fp = fopen("/var/log/eips/http.log", "w");
    if (aft->fp == NULL) {
        return -1;
    }

    *data = (void *)aft;
    return 0;
}

int LogHttplogThreadDeinit(ThreadVars *t, void *data)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    if (aft == NULL) {
        return 0;
    }

    if (aft->fp != NULL)
        fclose(aft->fp);

    /* clear memory */
    memset(aft, 0, sizeof(LogHttplogThread));

    free(aft);
    return 0;
}

void LogHttplogExitPrintStats(ThreadVars *tv, void *data) {
    LogHttplogThread *aft = (LogHttplogThread *)data;
    if (aft == NULL) {
        return;
    }

    printf(" - (%s) HTTP requests %u.\n", tv->name, aft->uri_cnt);
}

