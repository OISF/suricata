/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* alert debuglog
 *
 * TODO
 * - figure out a way to (thread) safely print detection engine info
 *   - maybe by having a log queue in the packet
 *   - maybe by accessing it just and hoping threading doesn't hurt
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

#include "eidps.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-print.h"

#include "pkt-var.h"

#include "util-unittest.h"

int AlertDebuglog (ThreadVars *, Packet *, void *, PacketQueue *);
int AlertDebuglogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
int AlertDebuglogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
int AlertDebuglogThreadInit(ThreadVars *, void*, void **);
int AlertDebuglogThreadDeinit(ThreadVars *, void *);
void AlertDebuglogExitPrintStats(ThreadVars *, void *);

void TmModuleAlertDebuglogRegister (void) {
    tmm_modules[TMM_ALERTDEBUGLOG].name = "AlertDebuglog";
    tmm_modules[TMM_ALERTDEBUGLOG].Init = AlertDebuglogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG].Func = AlertDebuglog;
    tmm_modules[TMM_ALERTDEBUGLOG].ExitPrintStats = AlertDebuglogExitPrintStats;
    tmm_modules[TMM_ALERTDEBUGLOG].Deinit = AlertDebuglogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG].RegisterTests = NULL;
}
/*
void TmModuleAlertDebuglogIPv4Register (void) {
    tmm_modules[TMM_ALERTDEBUGLOG4].name = "AlertDebuglogIPv4";
    tmm_modules[TMM_ALERTDEBUGLOG4].Init = AlertDebuglogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG4].Func = AlertDebuglogIPv4;
    tmm_modules[TMM_ALERTDEBUGLOG4].Deinit = AlertDebuglogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG4].RegisterTests = NULL;
}

void TmModuleAlertDebuglogIPv6Register (void) {
    tmm_modules[TMM_ALERTDEBUGLOG6].name = "AlertDebuglogIPv6";
    tmm_modules[TMM_ALERTDEBUGLOG6].Init = AlertDebuglogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG6].Func = AlertDebuglogIPv6;
    tmm_modules[TMM_ALERTDEBUGLOG6].Deinit = AlertDebuglogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG6].RegisterTests = NULL;
}
*/
typedef struct _AlertDebuglogThread {
    FILE *fp;
    u_int32_t alerts;
} AlertDebuglogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    u_int32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (u_int32_t) ts->tv_usec);
}

int AlertDebuglogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return 0;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    fprintf(aft->fp, "+================\n");
    fprintf(aft->fp, "TIME:              %s\n", timebuf);
    fprintf(aft->fp, "ALERT CNT:         %u\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];

        fprintf(aft->fp, "ALERT MSG [%02d]:    %s\n", i, pa->msg);
        fprintf(aft->fp, "ALERT GID [%02d]:    %u\n", i, pa->gid);
        fprintf(aft->fp, "ALERT SID [%02d]:    %u\n", i, pa->sid);
        fprintf(aft->fp, "ALERT REV [%02d]:    %u\n", i, pa->rev);
        fprintf(aft->fp, "ALERT PRIO [%02d]:   %u\n", i, pa->prio);
    }

    char srcip[16], dstip[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    fprintf(aft->fp, "SRC IP:            %s\n", srcip);
    fprintf(aft->fp, "DST IP:            %s\n", dstip);
    fprintf(aft->fp, "PROTO:             %u\n", IPV4_GET_IPPROTO(p));
    if (IPV4_GET_IPPROTO(p) == IPPROTO_TCP || IPV4_GET_IPPROTO(p) == IPPROTO_UDP) {
        fprintf(aft->fp, "SRC PORT:          %u\n", p->sp);
        fprintf(aft->fp, "DST PORT:          %u\n", p->dp);
    }

    /* flow stuff */
    fprintf(aft->fp, "FLOW:              to_server: %s, to_client %s\n",
        p->flowflags & FLOW_PKT_TOSERVER ? "TRUE" : "FALSE",
        p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE" : "FALSE");

    PktVar *pv = PktVarGet(p,"http_host");
    if (pv) {
        fprintf(aft->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->fp, pv->value, pv->value_len);
    }

    pv = PktVarGet(p,"http_ua");
    if (pv) {
        fprintf(aft->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->fp, pv->value, pv->value_len);
    }

    for (i = 0; i < p->http_uri.cnt; i++) {
        fprintf(aft->fp, "RAW URI [%2d]:      ", i);
        PrintRawUriFp(aft->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->fp, "\n");
        PrintRawDataFp(aft->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
    }

/* any stuff */
/* Sig details? */
/* pkt vars */
/* flowvars */

    aft->alerts += p->alerts.cnt;

    fprintf(aft->fp, "PACKET LEN:        %u\n", p->pktlen);
    fprintf(aft->fp, "PACKET:\n");
    PrintRawDataFp(aft->fp, p->pkt, p->pktlen);

    fflush(aft->fp);
    return 0;
}

int AlertDebuglogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return 0;

    aft->alerts += p->alerts.cnt;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        char srcip[46], dstip[46];

        inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

        fprintf(aft->fp, "%s  [**] [%u:%u:%u] %s [**] [Classification: fixme] [Priority: %u] {%u} %s:%u -> %s:%u\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
        fflush(aft->fp);
    }

    return 0;
}

int AlertDebuglog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertDebuglogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertDebuglogIPv6(tv, p, data, pq);
    }

    return 0;
}

int AlertDebuglogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertDebuglogThread *aft = malloc(sizeof(AlertDebuglogThread));
    if (aft == NULL) {
        return -1;
    }
    memset(aft, 0, sizeof(AlertDebuglogThread));

    /* XXX */
    aft->fp = fopen("/var/log/eidps/alert-debug.log", "w");
    if (aft->fp == NULL) {
        return -1;
    }

    *data = (void *)aft;
    return 0;
}

int AlertDebuglogThreadDeinit(ThreadVars *t, void *data)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    if (aft == NULL) {
        return 0;
    }

    if (aft->fp != NULL)
        fclose(aft->fp);

    /* clear memory */
    memset(aft, 0, sizeof(AlertDebuglogThread));

    free(aft);
    return 0;
}

void AlertDebuglogExitPrintStats(ThreadVars *tv, void *data) {
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    if (aft == NULL) {
        return;
    }

    printf(" - (%s) Alerts %u.\n", tv->name, aft->alerts);
}

