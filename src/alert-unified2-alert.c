/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-unittest.h"
#include "alert-unified2-alert.h"
#include "decode-ipv4.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/*prototypes*/
TmEcode Unified2Alert (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode Unified2AlertThreadInit(ThreadVars *, void *, void **);
TmEcode Unified2AlertThreadDeinit(ThreadVars *, void *);
int Unified2IPv4TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2IPv6TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2PacketTypeAlert(ThreadVars *, Packet *, void *);
void Unified2RegisterTests();
int Unified2AlertOpenFileCtx(LogFileCtx *, char *);

/**
 * Unified2 thread vars
 *
 * Used for storing file options.
 */
typedef struct Unified2AlertThread_ {
    LogFileCtx *file_ctx;   /** LogFileCtx pointer */
    uint32_t size_limit;    /**< file size limit */
    uint32_t size_current;  /**< file current size */
} Unified2AlertThread;

/**
 * Unified2 file header struct
 *
 * Used for storing file header options.
 */
typedef struct Unified2AlertFileHeader_ {
    uint32_t type;      /**< unified2 type header */
    uint32_t length;    /**< unified2 struct size length */
} Unified2AlertFileHeader;

/**
 * Unified2 Ipv4 struct
 *
 * Used for storing ipv4 type values.
 */
typedef struct AlertIPv4Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    uint32_t src_ip;                /**< source ip */
    uint32_t dst_ip;                /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv4Unified2;

/**
 * Unified2 Ipv6 type struct
 *
 * Used for storing ipv6 type values.
 */
typedef struct AlertIPv6Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    struct in6_addr src_ip;         /**< source ip */
    struct in6_addr dst_ip;         /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv6Unified2;

/**
 * Unified2 packet type struct
 *
 * Used for storing packet type values.
 */
typedef struct AlertUnified2Packet_ {
    uint32_t sensor_id;             /**< sensor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t packet_second;         /**< packet second */
    uint32_t packet_microsecond;    /**< packet microsecond */
    uint32_t linktype;              /**< link type */
    uint32_t packet_length;         /**< packet length */
    uint8_t packet_data[4];         /**< packet data */
} Unified2Packet;

void TmModuleUnified2AlertRegister (void) {
    tmm_modules[TMM_ALERTUNIFIED2ALERT].name = "Unified2Alert";
    tmm_modules[TMM_ALERTUNIFIED2ALERT].ThreadInit = Unified2AlertThreadInit;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].Func = Unified2Alert;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].ThreadDeinit = Unified2AlertThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].RegisterTests = Unified2RegisterTests;
}

/**
 *  \brief Function to close unified2 file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param aun Unified2 thread variable.
 */

int Unified2AlertCloseFile(ThreadVars *t, Unified2AlertThread *aun) {
    if (aun->file_ctx->fp != NULL) {
        fclose(aun->file_ctx->fp);
    }
    aun->size_current = 0;

    return 0;
}

/**
 *  \brief Function to rotate unified2 file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param aun Unified2 thread variable.
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2AlertRotateFile(ThreadVars *t, Unified2AlertThread *aun) {
    if (Unified2AlertCloseFile(t,aun) < 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC_ERROR,
                   "Error: Unified2AlertCloseFile failed");
        return -1;
    }
    if (Unified2AlertOpenFileCtx(aun->file_ctx,aun->file_ctx->config_file) < 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC_ERROR,
                   "Error: Unified2AlertOpenFileCtx, open new log file failed");
        return -1;
    }
    return 0;
}

TmEcode Unified2Alert (ThreadVars *t, Packet *p, void *data, PacketQueue *pq)
{
    int ret = 0;

    if(PKT_IS_IPV4(p))  {
        ret = Unified2IPv4TypeAlert (t, p, data, pq);
    }else if(PKT_IS_IPV6(p))  {
        ret = Unified2IPv6TypeAlert (t, p, data, pq);
    } else {
        /* we're only supporting IPv4 and IPv6 */
        return TM_ECODE_OK;
    }

    if (ret)
	return TM_ECODE_FAILED;

    return TM_ECODE_OK;
}

/**
 *  \brief Function to fill unified2 packet format into the file.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param p Packet struct used to decide for ipv4 or ipv6
 *  \param data Unified2 thread data.
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2PacketTypeAlert (ThreadVars *t, Packet *p, void *data)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    Unified2Packet phdr;
    Unified2AlertFileHeader hdr;
    int ret, len;
    char write_buffer[sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet) + IPV4_MAXPACKET_LEN];

    if(p->pktlen > 0)
        len = (sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet)) - 4 + p->pktlen;
    else
        len = (sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet)) - 4;

    memset(write_buffer,0,sizeof(write_buffer));

    memset(&hdr, 0, sizeof(Unified2AlertFileHeader));
    memset(&phdr, 0, sizeof(Unified2Packet));

    hdr.type = htonl(UNIFIED2_PACKET_TYPE);
    hdr.length = htonl(sizeof(Unified2Packet) -4 + p->pktlen);

    memcpy(write_buffer,&hdr,sizeof(Unified2AlertFileHeader));

    SCMutexLock(&aun->file_ctx->fp_mutex);
    if ((aun->size_current + (sizeof(hdr) + sizeof(phdr))) > aun->size_limit) {
        if (Unified2AlertRotateFile(t,aun) < 0)
        {
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }
    }
    SCMutexUnlock(&aun->file_ctx->fp_mutex);

    phdr.sensor_id = 0;
    phdr.linktype = htonl(p->datalink);
    phdr.event_id = 0;
    phdr.event_second = phdr.packet_second = htonl(p->ts.tv_sec);
    phdr.packet_microsecond = htonl(p->ts.tv_usec);
    phdr.packet_length = htonl(p->pktlen);

    memcpy(write_buffer+sizeof(Unified2AlertFileHeader),&phdr,sizeof(Unified2Packet) - 4);
    memcpy(write_buffer + sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet) - 4 , p->pkt, p->pktlen);

    ret = fwrite(write_buffer,len, 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
        return -1;
    }

    fflush(aun->file_ctx->fp);
    aun->size_current += len;

    return 0;
}

/**
 *  \brief Function to fill unified2 ipv6 ids type format into the file.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param p Packet struct used to decide for ipv4 or ipv6
 *  \param data Unified2 thread data.
 *  \param pq Packet queue
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2IPv6TypeAlert (ThreadVars *t, Packet *p, void *data, PacketQueue *pq)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    AlertIPv6Unified2 phdr;
    Unified2AlertFileHeader hdr;
    PacketAlert *pa;
    uint8_t ethh_offset = 0;
    int ret, len;
    char write_buffer[sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv6Unified2)];

    if (p->alerts.cnt == 0)
        return 0;

    len = (sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv6Unified2));

    memset(write_buffer,0,sizeof(write_buffer));

    memset(&hdr, 0, sizeof(Unified2AlertFileHeader));
    memset(&phdr, 0, sizeof(AlertIPv6Unified2));

    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_TYPE);
    hdr.length = htonl(sizeof(AlertIPv6Unified2));

    memcpy(write_buffer,&hdr,sizeof(Unified2AlertFileHeader));

    /* if we have no ethernet header (e.g. when using nfq), we have to create
     * one ourselves. */
    if (p->ethh == NULL) {
        ethh_offset = sizeof(EthernetHdr);
    }

    /* check and enforce the filesize limit */
    SCMutexLock(&aun->file_ctx->fp_mutex);
    if ((aun->size_current +(sizeof(hdr) +  sizeof(phdr))) > aun->size_limit) {
        if (Unified2AlertRotateFile(t,aun) < 0)
        {
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }
    }
    SCMutexUnlock(&aun->file_ctx->fp_mutex);

    /* XXX which one to add to this alert? Lets see how Snort solves this.
     * For now just take last alert. */
    pa = &p->alerts.alerts[p->alerts.cnt-1];

    /* fill the phdr structure */

    phdr.sensor_id = 0;
    phdr.event_id = 0;
    phdr.generator_id = htonl(pa->gid);
    phdr.signature_id = htonl(pa->sid);
    phdr.signature_revision = htonl(pa->rev);
    phdr.classification_id = htonl(pa->class);
    phdr.priority_id = htonl(pa->prio);
    phdr.event_second =  htonl(p->ts.tv_sec);
    phdr.event_microsecond = htonl(p->ts.tv_usec);
    phdr.src_ip = *(struct in6_addr*)GET_IPV6_SRC_ADDR(p);
    phdr.dst_ip = *(struct in6_addr*)GET_IPV6_DST_ADDR(p);
    phdr.protocol = IPV6_GET_NH(p);

    if(p->action == ACTION_DROP)
        phdr.packet_action = UNIFIED2_BLOCKED_FLAG;
    else
        phdr.packet_action = 0;

    switch(phdr.protocol)  {
        case IPPROTO_ICMP:
            if(p->icmpv4h)  {
                phdr.sp = htons(p->icmpv4h->type);
                phdr.dp = htons(p->icmpv4h->code);
            }
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            phdr.sp = htons(p->sp);
            phdr.dp = htons(p->dp);
            break;
        default:
            phdr.sp = 0;
            phdr.dp = 0;
            break;
    }

    memcpy(write_buffer+sizeof(Unified2AlertFileHeader),&phdr,sizeof(AlertIPv6Unified2));

    ret = fwrite(write_buffer,len, 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
        return -1;
    }

    fflush(aun->file_ctx->fp);
    aun->size_current += len;

    Unified2PacketTypeAlert(t, p, data);

    return 0;
}

/**
 *  \brief Function to fill unified2 ipv4 ids type format into the file.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param p Packet struct used to decide for ipv4 or ipv6
 *  \param data Unified2 thread data.
 *  \param pq Packet queue
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2IPv4TypeAlert (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    AlertIPv4Unified2 phdr;
    Unified2AlertFileHeader hdr;
    PacketAlert *pa;
    uint8_t ethh_offset = 0;
    int ret, len;
    char write_buffer[sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv4Unified2)];

    if (p->alerts.cnt == 0)
        return 0;

    len = (sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv4Unified2));

    memset(write_buffer,0,sizeof(write_buffer));
    memset(&hdr, 0, sizeof(Unified2AlertFileHeader));
    memset(&phdr, 0, sizeof(AlertIPv4Unified2));

    hdr.type = htonl(UNIFIED2_IDS_EVENT_TYPE);
    hdr.length = htonl(sizeof(AlertIPv4Unified2));

    memcpy(write_buffer,&hdr,sizeof(Unified2AlertFileHeader));

    /* if we have no ethernet header (e.g. when using nfq), we have to create
     * one ourselves. */
    if (p->ethh == NULL) {
        ethh_offset = sizeof(EthernetHdr);
    }

    /* check and enforce the filesize limit */
    SCMutexLock(&aun->file_ctx->fp_mutex);
    if ((aun->size_current +(sizeof(hdr) +  sizeof(phdr))) > aun->size_limit) {
        if (Unified2AlertRotateFile(tv,aun) < 0)
        {
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }
    }
    SCMutexUnlock(&aun->file_ctx->fp_mutex);

    /* XXX which one to add to this alert? Lets see how Snort solves this.
     * For now just take last alert. */
    pa = &p->alerts.alerts[p->alerts.cnt-1];

    /* fill the hdr structure */

    phdr.sensor_id = 0;
    phdr.event_id = 0;
    phdr.generator_id = htonl(pa->gid);
    phdr.signature_id = htonl(pa->sid);
    phdr.signature_revision = htonl(pa->rev);
    phdr.classification_id = htonl(pa->class);
    phdr.priority_id = htonl(pa->prio);
    phdr.event_second =  htonl(p->ts.tv_sec);
    phdr.event_microsecond = htonl(p->ts.tv_usec);
    phdr.src_ip = p->ip4h->ip_src.s_addr;
    phdr.dst_ip = p->ip4h->ip_dst.s_addr;
    phdr.protocol = IPV4_GET_RAW_IPPROTO(p->ip4h);

    if(p->action == ACTION_DROP)
        phdr.packet_action = UNIFIED2_BLOCKED_FLAG;
    else
        phdr.packet_action = 0;

    switch(phdr.protocol)  {
        case IPPROTO_ICMP:
            if(p->icmpv4h)  {
                phdr.sp = htons(p->icmpv4h->type);
                phdr.dp = htons(p->icmpv4h->code);
            }
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            phdr.sp = htons(p->sp);
            phdr.dp = htons(p->dp);
            break;
        default:
            phdr.sp = 0;
            phdr.dp = 0;
            break;
    }

    memcpy(write_buffer+sizeof(Unified2AlertFileHeader),&phdr,sizeof(AlertIPv4Unified2));

    ret = fwrite(write_buffer,len, 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
        return -1;
    }

    fflush(aun->file_ctx->fp);
    aun->size_current += len;

    Unified2PacketTypeAlert(tv, p, data);

    return 0;
}

/**
 *  \brief Thread init function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param initdata Unified2 thread initial data.
 *  \param data Unified2 thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */

TmEcode Unified2AlertThreadInit(ThreadVars *t, void *initdata, void **data)
{
    Unified2AlertThread *aun = malloc(sizeof(Unified2AlertThread));
    if (aun == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aun, 0, sizeof(Unified2AlertThread));
    if(initdata == NULL)
    {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC_ERROR, "Error getting context for "
                   "Unified2Alert.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = (LogFileCtx*) initdata;

    /* XXX make configurable */
    aun->size_limit = 10 * 1024 * 1024;

    *data = (void *)aun;
    return TM_ECODE_OK;
}

/**
 *  \brief Thread deinit function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param data Unified2 thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */

TmEcode Unified2AlertThreadDeinit(ThreadVars *t, void *data)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    if (aun == NULL) {
        goto error;
    }

    /* clear memory */
    memset(aun, 0, sizeof(Unified2AlertThread));
    free(aun);
    return TM_ECODE_OK;

error:
    /* clear memory */
    if (aun != NULL) {
        memset(aun, 0, sizeof(Unified2AlertThread));
        free(aun);
    }
    return TM_ECODE_FAILED;
}

/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *Unified2AlertInitCtx(char *config_file)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC_ERROR, "Unified2AlertInitCtx: "
                   "Couldn't create new file_ctx");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific Unified2Alert configuration */
    ret=Unified2AlertOpenFileCtx(file_ctx, config_file);

    if(ret < 0)
        return NULL;

    /** In Unified2AlertOpenFileCtx the second parameter should be the configuration file to use
    * but it's not implemented yet, so passing NULL to load the default
    * configuration
    */

    return file_ctx;
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param config_file for loading separate configs
 *  \return -1 if failure, 0 if succesful
 * */
int Unified2AlertOpenFileCtx(LogFileCtx *file_ctx, char *config_file)
{
    char *filename = NULL;
    if (file_ctx->filename != NULL)
        filename = file_ctx->filename;
    else
        filename = file_ctx->filename = malloc(PATH_MAX); /* XXX some sane default? */

    if (config_file == NULL) {
        /** Separate config files not implemented at the moment,
        * but it must be able to load from separate config file.
        * Load the default configuration.
        */

        /** get the time so we can have a filename with seconds since epoch */
        struct timeval ts;
        memset(&ts, 0x00, sizeof(struct timeval));
        TimeGet(&ts);

        /* create the filename to use */
        char *log_dir;
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;

        snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, log_dir, "unified2.alert", (uint32_t)ts.tv_sec);

        /* XXX filename & location */
        file_ctx->fp = fopen(filename, "wb");
        if (file_ctx->fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", filename,
                       strerror(errno));
            return -1;
        }
    }

    return 0;
}


#ifdef UNITTESTS

/**
 *  \test Test the ethernet+ipv4+tcp unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test01 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    LogFileCtx *lf;

    uint8_t raw_ipv4_tcp[] = {
        0x00, 0x14, 0xbf, 0xe8, 0xcb, 0x26, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x8c, 0x55, 0x40, 0x00, 0x40, 0x06,
        0x69, 0x86, 0xc0, 0xa8, 0x0a, 0x68, 0x4a, 0x7d,
        0x2f, 0x53, 0xc2, 0x40, 0x00, 0x50, 0x1f, 0x00,
        0xa4, 0xd4, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x3d, 0x4e, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x1c,
        0x28, 0x81, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06};
    Packet p;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(&p, 0, sizeof(Packet));

    p.alerts.cnt++;
    p.alerts.alerts[p.alerts.cnt-1].sid = 1;
    p.alerts.alerts[p.alerts.cnt-1].gid = 1;
    p.alerts.alerts[p.alerts.cnt-1].rev = 1;
    p.pktlen = sizeof(raw_ipv4_tcp);

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, &p, raw_ipv4_tcp, sizeof(raw_ipv4_tcp), &pq);

    FlowShutdown();

    lf=Unified2AlertInitCtx(NULL);
    if(lf == NULL)
        return 0;
    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2Alert(&tv, &p, data, &pq);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1)
        return 0;

    if(LogFileFreeCtx(lf)==0)
        return 0;
    return 1;
}

/**
 *  \test Test the ethernet+ipv6+tcp unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test02 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    LogFileCtx *lf;

    uint8_t raw_ipv6_tcp[] = {
        0x00, 0x11, 0x25, 0x82, 0x95, 0xb5, 0x00, 0xd0,
        0x09, 0xe3, 0xe8, 0xde, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x28, 0x06, 0x40, 0x20, 0x01,
        0x06, 0xf8, 0x10, 0x2d, 0x00, 0x00, 0x02, 0xd0,
        0x09, 0xff, 0xfe, 0xe3, 0xe8, 0xde, 0x20, 0x01,
        0x06, 0xf8, 0x09, 0x00, 0x07, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xe7, 0x41,
        0x00, 0x50, 0xab, 0xdc, 0xd6, 0x60, 0x00, 0x00,
        0x00, 0x00, 0xa0, 0x02, 0x16, 0x80, 0x41, 0xa2,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xa0, 0x04, 0x02,
        0x08, 0x0a, 0x00, 0x0a, 0x22, 0xa8, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x03, 0x03, 0x05 };
    Packet p;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(&p, 0, sizeof(Packet));

    p.alerts.cnt++;
    p.alerts.alerts[p.alerts.cnt-1].sid = 1;
    p.alerts.alerts[p.alerts.cnt-1].gid = 1;
    p.alerts.alerts[p.alerts.cnt-1].rev = 1;
    p.pktlen = sizeof(raw_ipv6_tcp);

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, &p, raw_ipv6_tcp, sizeof(raw_ipv6_tcp), &pq);

    FlowShutdown();

    lf=Unified2AlertInitCtx(NULL);
    if(lf == NULL)
        return 0;
    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if(ret == -1)
        return 0;
    ret = Unified2Alert(&tv, &p, data, &pq);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1)
        return 0;

    if(LogFileFreeCtx(lf)==0)
        return 0;

    return 1;
}


/**
 *  \test Test the GRE unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test03 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    LogFileCtx *lf;

    uint8_t raw_gre[] = {
        0x00, 0x0e, 0x50, 0x06, 0x42, 0x96, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x74, 0x35, 0xa2, 0x40, 0x00, 0x40, 0x2f,
        0xef, 0xcb, 0x0a, 0x00, 0x00, 0x64, 0x0a, 0x00,
        0x00, 0x8a, 0x30, 0x01, 0x88, 0x0b, 0x00, 0x54,
        0x00, 0x00, 0x00, 0x18, 0x29, 0x5f, 0xff, 0x03,
        0x00, 0x21, 0x45, 0x00, 0x00, 0x50, 0xf4, 0x05,
        0x40, 0x00, 0x3f, 0x06, 0x20, 0xb8, 0x50, 0x7e,
        0x2b, 0x2d, 0xd4, 0xcc, 0xd6, 0x72, 0x0a, 0x92,
        0x1a, 0x0b, 0xc9, 0xaf, 0x24, 0x02, 0x8c, 0xdd,
        0x45, 0xf6, 0x80, 0x18, 0x21, 0xfc, 0x10, 0x7c,
        0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x08, 0x19,
        0x1a, 0xda, 0x84, 0xd6, 0xda, 0x3e, 0x50, 0x49,
        0x4e, 0x47, 0x20, 0x73, 0x74, 0x65, 0x72, 0x6c,
        0x69, 0x6e, 0x67, 0x2e, 0x66, 0x72, 0x65, 0x65,
        0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x65, 0x74,
        0x0d, 0x0a};
    Packet p;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(&p, 0, sizeof(Packet));

    p.alerts.cnt++;
    p.alerts.alerts[p.alerts.cnt-1].sid = 1;
    p.alerts.alerts[p.alerts.cnt-1].gid = 1;
    p.alerts.alerts[p.alerts.cnt-1].rev = 1;
    p.pktlen = sizeof(raw_gre);

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, &p, raw_gre, sizeof(raw_gre), &pq);

    FlowShutdown();

    lf=Unified2AlertInitCtx(NULL);
    if(lf == NULL)
        return 0;
    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if(ret == -1)
        return 0;
    ret = Unified2Alert(&tv, &p, data, &pq);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1)
        return 0;

    if(LogFileFreeCtx(lf)==0)
        return 0;

    return 1;
}

/**
 *  \test Test the PPP unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test04 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    LogFileCtx *lf;

    uint8_t raw_ppp[] = {
        0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c,
        0x4d, 0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17,
        0xbf, 0x01, 0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03,
        0xea, 0x37, 0x00, 0x17, 0x6d, 0x0b, 0xba, 0xc3,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0x10, 0x20,
        0xdd, 0xe1, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4};
    Packet p;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(&p, 0, sizeof(Packet));

    p.alerts.cnt++;
    p.alerts.alerts[p.alerts.cnt-1].sid = 1;
    p.alerts.alerts[p.alerts.cnt-1].gid = 1;
    p.alerts.alerts[p.alerts.cnt-1].rev = 1;
    p.pktlen = sizeof(raw_ppp);

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &dtv, &p, raw_ppp, sizeof(raw_ppp), &pq);

    FlowShutdown();

    lf=Unified2AlertInitCtx(NULL);
    if(lf == NULL)
        return 0;
    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if(ret == -1)
        return 0;
    ret = Unified2Alert(&tv, &p, data, &pq);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1)
        return 0;

    if(LogFileFreeCtx(lf)==0)
        return 0;

    return 1;
}

/**
 *  \test Test the ethernet+ipv4+tcp droped unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test05 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    LogFileCtx *lf;

    uint8_t raw_ipv4_tcp[] = {
        0x00, 0x14, 0xbf, 0xe8, 0xcb, 0x26, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x8c, 0x55, 0x40, 0x00, 0x40, 0x06,
        0x69, 0x86, 0xc0, 0xa8, 0x0a, 0x68, 0x4a, 0x7d,
        0x2f, 0x53, 0xc2, 0x40, 0x00, 0x50, 0x1f, 0x00,
        0xa4, 0xd4, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x3d, 0x4e, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x1c,
        0x28, 0x81, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06};
    Packet p;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(&p, 0, sizeof(Packet));

    p.alerts.cnt++;
    p.alerts.alerts[p.alerts.cnt-1].sid = 1;
    p.alerts.alerts[p.alerts.cnt-1].gid = 1;
    p.alerts.alerts[p.alerts.cnt-1].rev = 1;
    p.pktlen = sizeof(raw_ipv4_tcp);

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, &p, raw_ipv4_tcp, sizeof(raw_ipv4_tcp), &pq);

    FlowShutdown();

    p.action = ACTION_DROP;

    lf=Unified2AlertInitCtx(NULL);
    if(lf == NULL)
        return 0;
    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if(ret == -1)
        return 0;
    ret = Unified2Alert(&tv, &p, data, &pq);
    if(ret == TM_ECODE_FAILED)
        return 0;
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == TM_ECODE_FAILED)
        return 0;

    if(LogFileFreeCtx(lf)==0)
        return 0;

    return 1;
}

/**
 *  \test Test the Rotate process
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int Unified2TestRotate01(void)
{
    int ret = 0;
    int r = 0;
    ThreadVars tv;
    LogFileCtx *lf;
    void *data = NULL;

    lf = Unified2AlertInitCtx(NULL);
    if (lf == NULL)
        return 0;
    char *filename = strdup(lf->filename);

    memset(&tv, 0, sizeof(ThreadVars));

    if (lf == NULL)
        return 0;

    ret = Unified2AlertThreadInit(&tv, lf, &data);
    if (ret == TM_ECODE_FAILED) {
        LogFileFreeCtx(lf);
        return 0;
    }

    TimeSetIncrementTime(1);

    ret = Unified2AlertRotateFile(&tv, data);
    if (ret == -1)
        goto error;

    if (strcmp(filename, lf->filename) == 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC_ERROR,
                   "filename \"%s\" == \"%s\": ", filename, lf->filename);
        goto error;
    }

    r = 1;

error:
    Unified2AlertThreadDeinit(&tv, data);
    if (lf != NULL) LogFileFreeCtx(lf);
    if (filename != NULL) free(filename);
    return r;
}
#endif

/**
 * \brief this function registers unit tests for Unified2
 */
void Unified2RegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("Unified2Test01 -- Ipv4 test", Unified2Test01, 1);
    UtRegisterTest("Unified2Test02 -- Ipv6 test", Unified2Test02, 1);
    UtRegisterTest("Unified2Test03 -- GRE test", Unified2Test03, 1);
    UtRegisterTest("Unified2Test04 -- PPP test", Unified2Test04, 1);
    UtRegisterTest("Unified2Test05 -- Inline test", Unified2Test05, 1);
    UtRegisterTest("Unified2TestRotate01 -- Rotate File", Unified2TestRotate01, 1);
#endif /* UNITTESTS */
}
