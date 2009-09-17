/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* alert fastlog
 *
 * Logs alerts in a line based text format compatible to Snort's
 * alert_fast format.
 *
 * TODO
 * - Print the protocol as a string
 * - Support classifications
 * - Support more than just IPv4/IPv4 TCP/UDP.
 * - Print [drop] as well if appropriate
 */

#include "eidps-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-unittest.h"

#define DEFAULT_LOG_FILENAME "fast.log"

int AlertFastlog (ThreadVars *, Packet *, void *, PacketQueue *);
int AlertFastlogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
int AlertFastlogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
int AlertFastlogThreadInit(ThreadVars *, void *, void **);
int AlertFastlogThreadDeinit(ThreadVars *, void *);
void AlertFastlogExitPrintStats(ThreadVars *, void *);

void TmModuleAlertFastlogRegister (void) {
    tmm_modules[TMM_ALERTFASTLOG].name = "AlertFastlog";
    tmm_modules[TMM_ALERTFASTLOG].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG].Func = AlertFastlog;
    tmm_modules[TMM_ALERTFASTLOG].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG].RegisterTests = NULL;
}

void TmModuleAlertFastlogIPv4Register (void) {
    tmm_modules[TMM_ALERTFASTLOG4].name = "AlertFastlogIPv4";
    tmm_modules[TMM_ALERTFASTLOG4].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG4].Func = AlertFastlogIPv4;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG4].RegisterTests = NULL;
}

void TmModuleAlertFastlogIPv6Register (void) {
    tmm_modules[TMM_ALERTFASTLOG6].name = "AlertFastlogIPv6";
    tmm_modules[TMM_ALERTFASTLOG6].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG6].Func = AlertFastlogIPv6;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG6].RegisterTests = NULL;
}

typedef struct AlertFastlogThread_ {
    FILE *fp;
    uint32_t alerts;
} AlertFastlogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

int AlertFastlogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return 0;

    aft->alerts += p->alerts.cnt;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        char srcip[16], dstip[16];

        inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

        fprintf(aft->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: fixme] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV4_GET_IPPROTO(p), srcip, p->sp, dstip, p->dp);
        fflush(aft->fp);
    }
    return 0;
}

int AlertFastlogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
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

        fprintf(aft->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: fixme] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
        fflush(aft->fp);
    }

    return 0;
}

int AlertFastlog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertFastlogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertFastlogIPv6(tv, p, data, pq);
    }

    return 0;
}

int AlertFastlogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertFastlogThread *aft = malloc(sizeof(AlertFastlogThread));
    if (aft == NULL) {
        return -1;
    }
    memset(aft, 0, sizeof(AlertFastlogThread));

    char log_path[PATH_MAX], *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    snprintf(log_path, PATH_MAX, "%s/%s", log_dir, DEFAULT_LOG_FILENAME);
    aft->fp = fopen(log_path, "w");
    if (aft->fp == NULL) {
        printf("ERROR: failed to open %s: %s\n", log_path, strerror(errno));
        return -1;
    }

    *data = (void *)aft;
    return 0;
}

int AlertFastlogThreadDeinit(ThreadVars *t, void *data)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    if (aft == NULL) {
        return 0;
    }

    if (aft->fp != NULL)
        fclose(aft->fp);

    /* clear memory */
    memset(aft, 0, sizeof(AlertFastlogThread));

    free(aft);
    return 0;
}

void AlertFastlogExitPrintStats(ThreadVars *tv, void *data) {
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    if (aft == NULL) {
        return;
    }

    printf(" - (%s) Alerts %" PRIu32 ".\n", tv->name, aft->alerts);
}

