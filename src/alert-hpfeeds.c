/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <hpfeeds.h>
#include <jansson.h>

#include "suricata-common.h"
#include "debug.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"

#include "output.h"
#include "alert-hpfeeds.h"

#include "util-classification-config.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"

#ifndef OS_WIN32

#define MODULE_NAME                             "AlertHPFeeds"
#define HPFEEDS_DEFAULT_PORT                    10000
#define READ_BLOCK_SIZE                         32767
#define BUF_LEN                                 32

#define HPFEEDS_NOK 0
#define HPFEEDS_AUTH_DONE 1
#define HPFEEDS_READY 2

typedef enum { 
  S_INIT,
  S_AUTH,
  S_AUTH_DONE,
  S_ERROR,
  S_TERMINATE
} hpfeeds_session_state_t;

/* HPFeeds data used in every thread */
typedef struct AlertHPFeedsCtx_ {
    /* hpfeeds connection parameter */
    char        *hpfeeds_host;
    char        *hpfeeds_ident;
    char        *hpfeeds_secret;
    char        *hpfeeds_channel;
    intmax_t    hpfeeds_port;

    /* Reconnect ?! */
    int         reconnect;

    /* socket */
    int         sock;
    struct      pollfd pfd;

    /* Connection status */
    int         status;

    /* Mutex used for synchronization */
    SCMutex     mutex;
} AlertHPFeedsCtx;

/* Thread structure */
typedef struct AlertHPFeedsThread_ {
    AlertHPFeedsCtx *ctx;
} AlertHPFeedsThread;

void HPFeedsPublish(json_t *json, AlertHPFeedsCtx *config);
void HPFeedsConnect(AlertHPFeedsCtx *config, int reconnect);
void HPFeedsCloseConnection(int * sock);

/**
 * \brief Function to clear the memory of the output context 
 *
 * \param output_ctx pointer to the output context to be cleared
 */

static void AlertHPFeedsDeInitCtx(OutputCtx *output_ctx)
{
    AlertHPFeedsCtx *ctx = (AlertHPFeedsCtx *)output_ctx->data;

    if (ctx->hpfeeds_host) SCFree(ctx->hpfeeds_host);
    if (ctx->hpfeeds_ident) SCFree(ctx->hpfeeds_ident);
    if (ctx->hpfeeds_secret) SCFree(ctx->hpfeeds_secret);
    if (ctx->hpfeeds_channel) SCFree(ctx->hpfeeds_channel);

    HPFeedsCloseConnection(&ctx->sock);

    SCFree(ctx);
}

/**
 * \brief Create a new AlertHPFeedsCtx.
 *
 * \param conf The configuration node for this output.
 * \return A OutputCtx pointer on success, NULL on failure.
 */

OutputCtx *AlertHPFeedsInitCtx(ConfNode *conf)
{
    OutputCtx *output_ctx;
    AlertHPFeedsCtx *ctx;

    ctx = SCMalloc(sizeof(AlertHPFeedsCtx));

    if (unlikely(ctx == NULL))
        SCReturnPtr(NULL, "AlertHPFeedsCtx");

    ctx->status = HPFEEDS_NOK;
    ctx->hpfeeds_port = HPFEEDS_DEFAULT_PORT;
    ctx->sock = -1;

    ConfGetChildValue(conf, "host", &ctx->hpfeeds_host);
    ConfGetChildValue(conf, "ident", &ctx->hpfeeds_ident);
    ConfGetChildValue(conf, "secret", &ctx->hpfeeds_secret);
    ConfGetChildValue(conf, "channel", &ctx->hpfeeds_channel);
    ConfGetChildValueInt(conf, "port", &ctx->hpfeeds_port);
    ConfGetChildValueBool(conf, "reconnect", &ctx->reconnect);

    SCMutexInit(&ctx->mutex, NULL);

    output_ctx = SCMalloc(sizeof(OutputCtx));

    if (unlikely(output_ctx == NULL)) {
        SCFree(ctx);
        SCReturnPtr(NULL, "AlertPHPFeedsCtx");
    }

    output_ctx->data = ctx;
    output_ctx->DeInit = AlertHPFeedsDeInitCtx;

    if (ctx->hpfeeds_host && ctx->hpfeeds_ident && ctx->hpfeeds_secret && ctx->hpfeeds_channel)
        HPFeedsConnect(ctx, 0); 

    SCReturnPtr((void*)output_ctx, "OutputCtx");
}

/**
 * \brief Function to initialize the AlertHPFeedsThread and sets the output
 *        context pointer
 *
 * \param tv            Pointer to the threadvars
 * \param initdata      Pointer to the output context
 * \param data          pointer to pointer to point to the AlertHPFeedsThread
 */

static TmEcode AlertHPFeedsThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertHPFeedsThread *thread_ctx;

    SCEnter();

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for hpfeeds.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    thread_ctx = SCMalloc(sizeof(AlertHPFeedsThread));

    if (unlikely(thread_ctx == NULL))
        SCReturnInt(TM_ECODE_FAILED);

    memset(thread_ctx, 0, sizeof(AlertHPFeedsThread));

    /** Use the Ouput Context */
    thread_ctx->ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)thread_ctx;

    SCReturnInt(TM_ECODE_OK);
    return TM_ECODE_OK;
}

/**
 * \brief Function to deinitialize the AlertHPFeedsThread
 *
 * \param tv            Pointer to the threadvars
 * \param data          pointer to the AlertHPFeedsThread to be cleared
 */

static TmEcode AlertHPFeedsThreadDeinit(ThreadVars *t, void *data)
{
    AlertHPFeedsThread *thread_ctx = (AlertHPFeedsThread *)data;

    if (thread_ctx == NULL)
        return TM_ECODE_OK;

    /* clear memory */
    memset(thread_ctx, 0, sizeof(AlertHPFeedsThread));
    SCFree(thread_ctx);

    return TM_ECODE_OK;
}

/* Input is packet and an nine-byte (including NULL) character array.  Results
 * are put into the character array.
 */

void CreateTCPFlagString(const Packet * p, char *flagBuffer)
{
    /* parse TCP flags */
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_CWR)  ? '1' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_ECN)  ? '2' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_URG)  ? 'U' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_ACK)  ? 'A' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_PUSH) ? 'P' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_RST)  ? 'R' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_SYN)  ? 'S' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_FIN)  ? 'F' : '*');
    *flagBuffer = '\0';
}

/**
 * \brief   Function which is called to create json alert
 *
 * \param tv    Pointer to the threadvars
 * \param p     Pointer to the packet
 * \param data  pointer to the AlertHPFeedsThread
 *
 * \return On succes return TM_ECODE_OK
 */

static int CreatePacketData(ThreadVars *tv, const Packet *p, json_t * js)
{
    char srcip[46], dstip[46];
    char construct_buf[BUF_LEN];

    char timestamp[64];
    struct tm* lt = localtime(&p->ts.tv_sec);
    strftime((char*)timestamp, 64, "%Y/%m/%d %H:%M:%S", lt);

    char timestamp_usec[68];

    snprintf(timestamp_usec, 68, "%s.%d", timestamp, (int)p->ts.tv_usec);

    json_object_set_new(js, "timestamp", json_string((char *)timestamp_usec));

    srcip[0] = '\0';
    dstip[0] = '\0';

    /* IPv4/v6 */
    if (PKT_IS_IPV4(p)) {

        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

        json_object_set_new(js, "destination_ip", json_string(dstip));
        json_object_set_new(js, "source_ip", json_string(srcip));

        json_object_set_new(js, "ip_tos", json_integer(IPV4_GET_IPTOS(p)));
        json_object_set_new(js, "ip_ttl", json_integer(IPV4_GET_IPTTL(p)));
        json_object_set_new(js, "ip_id", json_integer(IPV4_GET_IPID(p)));


    } else if (PKT_IS_IPV6(p)) {

      PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
      PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

      json_object_set_new(js, "destination_ip", json_string(dstip));
      json_object_set_new(js, "source_ip", json_string(srcip));

    }

    char proto[16];
    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "%03" PRIu32, IP_GET_IPPROTO(p));
    }

    json_object_set_new(js, "proto", json_string(proto));

    /* Ethernet */
    if (p->ethh != NULL) {

      snprintf(construct_buf, BUF_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", p->ethh->eth_src[0],
              p->ethh->eth_src[1], p->ethh->eth_src[2], p->ethh->eth_src[3],
              p->ethh->eth_src[4], p->ethh->eth_src[5]);
      json_object_set_new(js, "eth_src", json_string((char *) construct_buf));

      snprintf(construct_buf, BUF_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", p->ethh->eth_dst[0],
              p->ethh->eth_dst[1], p->ethh->eth_dst[2], p->ethh->eth_dst[3],
              p->ethh->eth_dst[4], p->ethh->eth_dst[5]);
      json_object_set_new(js, "eth_dst", json_string((char *) construct_buf));

      snprintf(construct_buf, BUF_LEN, "0x%X", ntohs(p->ethh->eth_type)); 
      json_object_set_new(js, "eth_type", json_string((char *)construct_buf));

      snprintf(construct_buf, BUF_LEN,"0x%X", p->pktlen);
      json_object_set_new(js, "eth_len", json_string((char *)construct_buf));
    }


    /* TCP */
    if (PKT_IS_TCP(p)) {

      snprintf(construct_buf, BUF_LEN,"0x%X", p->tcph->th_seq);
      json_object_set_new(js, "tcp_seq", json_string((char *)construct_buf));

      snprintf(construct_buf, BUF_LEN, "0x%X", p->tcph->th_ack);
      json_object_set_new(js, "tcp_ack", json_string((char *)construct_buf));

      snprintf(construct_buf, BUF_LEN, "0x%lX", (u_long)ntohl(p->tcph->th_win));
      json_object_set_new(js, "tcp_win", json_string((char *)construct_buf));

      json_object_set_new(js, "tcp_len", json_integer(TCP_GET_RAW_OFFSET(p->tcph) << 2));

      json_object_set_new(js, "source_port", json_integer(p->sp));
      json_object_set_new(js, "destination_port", json_integer(p->dp));

      char tcpflags[9];
      CreateTCPFlagString(p, tcpflags);
      json_object_set_new(js, "tcp_flags", json_string((char *)tcpflags));
    }

    /* UDP */
    else if (PKT_IS_UDP(p)) {
      json_object_set_new(js, "udp_len", json_integer(UDP_GET_LEN(p)));
      json_object_set_new(js, "source_port", json_integer(p->sp));
      json_object_set_new(js, "destination_port", json_integer(p->dp));
    }

    /* ICMPv4/v6 */
    else if (p->proto == IPPROTO_ICMP) {
    
      if (PKT_IS_ICMPV4(p)) {
        
        json_object_set_new(js, "icmp_version", json_integer(4));      
        json_object_set_new(js, "icmp_id", json_integer(ICMPV4_GET_ID(p)));
        json_object_set_new(js, "icmp_seq", json_integer(ICMPV4_GET_SEQ(p)));
        json_object_set_new(js, "icmp_type",json_integer(ICMPV4_GET_TYPE(p)));
        json_object_set_new(js, "icmp_code",json_integer(ICMPV4_GET_CODE(p)));

      } else if(PKT_IS_ICMPV6(p)) {

        json_object_set_new(js, "icmp_version", json_integer(6));
        json_object_set_new(js, "icmp_id", json_integer(ICMPV6_GET_ID(p)));
        json_object_set_new(js, "icmp_seq", json_integer(ICMPV6_GET_SEQ(p)));
        json_object_set_new(js, "icmp_type",json_integer(ICMPV6_GET_TYPE(p)));
        json_object_set_new(js, "icmp_code",json_integer(ICMPV6_GET_CODE(p)));
      }

    }
    
    return 1;
   
}

static int AlertHPFeedsCondition(ThreadVars *tv, const Packet *p)
{
    return (p->alerts.cnt > 0 ? TRUE : FALSE);
}

static int AlertHPFeedsLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    AlertHPFeedsThread *thread_ctx = (AlertHPFeedsThread *)thread_data;
    AlertHPFeedsCtx *ctx = (AlertHPFeedsCtx *)thread_ctx->ctx;

    /* Return if packet is NULL or socket isn't open */
    if(p == NULL || ctx->sock == -1)
        return TM_ECODE_OK;
    
    SCMutex *mtx = &ctx->mutex;

    SCMutexLock(mtx);

    json_t *record = json_object();
    json_object_set_new(record, "sensor", json_string(ctx->hpfeeds_ident));

    if (!CreatePacketData(tv, p, record))
    {
      json_decref(record);
      SCMutexUnlock(mtx);
      return TM_ECODE_OK;  
    }

    int i = 0;

    for ( ; i < p->alerts.cnt; i++) {

        const PacketAlert *pa = &p->alerts.alerts[i];

        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char *action = "allowed";
        if (pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "blocked";
        }

        json_object_set_new(record, "action", json_string(action));

        // header
        // priority
        // classification

        json_object_set_new(record, "signature_id",  json_integer(pa->s->id));
        json_object_set_new(record, "signature_rev", json_integer(pa->s->rev));
        json_object_set_new(record, "signature",     json_string((pa->s->msg) ? pa->s->msg : ""));
    }

    HPFeedsPublish(record, ctx);

    json_decref(record);

    SCMutexUnlock(mtx);

    return TM_ECODE_OK;
}


/* == Reused function for hpfeeds ==
 *
 * Functions: HPFeedsReadMsg 
 *            HPFeedsGetError
 *            HPFeedsCloseConnection
 *            HPFeedsConnect
 *            HPFeedsPublish
 */

u_char *HPFeedsReadMsg(int sock)
{
  u_char *buffer;
  int msglen;

  int len;
  int templen;
  char tempbuf[READ_BLOCK_SIZE];

  if (read(sock, &msglen, 4) != 4) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal read()");
    return NULL;
  }

  if ((buffer = malloc(ntohl(msglen))) == NULL) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal malloc()");
    return NULL;
  }

  *(unsigned int *) buffer = msglen;
  msglen = ntohl(msglen);

  len = 4;
  templen = len;
  while ((templen > 0) && (len < msglen)) 
  {
    templen = read(sock, tempbuf, READ_BLOCK_SIZE);
    memcpy(buffer + len, tempbuf, templen);
    len += templen;
  }

  if (len != msglen) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal read()");
    free(buffer);
    return NULL;
  }

  return buffer;
}

void HPFeedsGetError(hpf_msg_t *msg, int sock) 
{

  u_char *errmsg;

  if (msg) 
  {
    if ((errmsg = calloc(1, msg->hdr.msglen - sizeof(msg->hdr))) == NULL) {
      SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal write()");
      hpf_msg_delete(msg);
      return;
    }
          
    memcpy(errmsg, msg->data, ntohl(msg->hdr.msglen) - sizeof(msg->hdr));

    SCLogNotice("alert-hpfeeds: server error: '%s'", errmsg);

    free(errmsg);
    hpf_msg_delete(msg);
  }
}


void HPFeedsCloseConnection(int *sock)
{
  if (*sock != -1) {
    close(*sock);
    *sock = -1;
  }
}

void HPFeedsConnect(AlertHPFeedsCtx *config, int reconnect) 
{

  /* socket already on - returning */
  if (config->sock != -1) return;

  hpf_msg_t *msg = NULL;
  hpf_chunk_t *chunk;

  unsigned int nonce = 0;

  struct hostent *he;
  struct sockaddr_in host;

  memset(&host, 0, sizeof(struct sockaddr_in));
  host.sin_family = AF_INET;
  host.sin_port = htons(config->hpfeeds_port);

  if ((he = gethostbyname((char *)config->hpfeeds_host)) == NULL) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal gethostbyname()\n");
    return;
  }

  host.sin_addr = *(struct in_addr *) he->h_addr;

  if ((config->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal socket()");
    return;
  }

  if (connect(config->sock, (struct sockaddr *) &host, sizeof(host)) == -1) {
    SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal connect()");
    return;
  }

  /* Set poll fd */
  config->pfd.fd = config->sock;
  config->pfd.events = POLLIN;
  config->pfd.revents = 0;

  /* Set connection keep alive */
  int optval = 1;

  if(setsockopt(config->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) 
  {
      SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal setsockopt()");
      HPFeedsCloseConnection(&config->sock);
      return;
   }

  hpfeeds_session_state_t hpfeeds_state = S_INIT;

  for (;;) 
  { 

    switch (hpfeeds_state) 
    {

      case S_INIT:

        if ((msg = (hpf_msg_t *) HPFeedsReadMsg(config->sock)) == NULL) {
          HPFeedsCloseConnection(&config->sock);
          break;
        }

        switch (msg->hdr.opcode) 
        {

          case OP_INFO:

            chunk = hpf_msg_get_chunk((u_char *)msg + sizeof(msg->hdr), ntohl(msg->hdr.msglen) - sizeof(msg->hdr));

            if (!chunk) 
            { 
              SCLogNotice("alert-hpfeeds: invalid message format");
              hpfeeds_state = S_TERMINATE;
              break;
            }

            nonce = *(unsigned int *) ((u_char *)msg + sizeof(msg->hdr) + chunk->len + 1);
            hpfeeds_state = S_AUTH;

            hpf_msg_delete(msg);
            break;

          case OP_ERROR:
            hpfeeds_state = S_ERROR;
            break;

          default:
            hpf_msg_delete(msg);
            hpfeeds_state = S_TERMINATE;
            SCLogNotice("alert-hpfeeds: unknown server message (type %u)", msg->hdr.opcode);
            break;
        }

      case S_AUTH:

        SCLogNotice("alert-hpfeeds: sending authentication.");

        msg = hpf_msg_auth(nonce, (u_char *) config->hpfeeds_ident, strlen(config->hpfeeds_ident) \
                           ,(u_char *) config->hpfeeds_secret, strlen(config->hpfeeds_secret));

        if (write(config->sock, (u_char *) msg, ntohl(msg->hdr.msglen)) == -1) {
          SCLogError(SC_LOG_ERROR,"alert-hpfeeds: Fatal write()");
          hpfeeds_state = S_TERMINATE;
          hpf_msg_delete(msg);
          break;
        }

        if (reconnect == 0) {

          int rv = poll(&config->pfd, 1, 1000);

          if (rv > 0 && config->pfd.revents && POLLIN) 
          {
            hpfeeds_state = S_ERROR;

            msg = (hpf_msg_t *) HPFeedsReadMsg(config->sock);
            break;
          }
        }

        hpfeeds_state = S_AUTH_DONE;
        config->status = HPFEEDS_AUTH_DONE;

        SCLogNotice("alert-hpfeeds: authentication done.");
        hpf_msg_delete(msg);

        break;

      case S_ERROR:

        if (msg) {
          HPFeedsGetError(msg, config->sock);
        }

        hpfeeds_state = S_TERMINATE;
        break;

      case S_TERMINATE:
      default:
        HPFeedsCloseConnection(&config->sock);
        SCLogNotice("alert-hpfeeds: connection terminated...");
        break;
      }

    if (hpfeeds_state == S_AUTH_DONE || config->sock == -1)
      break;
  }
}


void HPFeedsPublish(json_t *json, AlertHPFeedsCtx *config) 
{

  char *data = json_dumps(json, 0);
  unsigned int len = strlen(data);
 
  hpf_msg_t *msg;

  msg = hpf_msg_publish((u_char *)config->hpfeeds_ident, strlen(config->hpfeeds_ident) \
                        ,(u_char *)config->hpfeeds_channel, strlen(config->hpfeeds_channel), (u_char *)data, len);
  
  if (write(config->sock, (char *) msg, ntohl(msg->hdr.msglen)) == -1) {

   SCLogNotice("alert-hpfeeds: Publish failed on write.\n");
   HPFeedsCloseConnection(&config->sock);

   if (config->reconnect) {
    HPFeedsConnect(config, config->reconnect); 
    HPFeedsPublish(json, config);
   }

   free(data);
   hpf_msg_delete(msg);

   return;
  }

  /* Do another socket poll - in case of wrong channel */
  if (config->status != HPFEEDS_READY) 
  {

    int rv = poll(&config->pfd, 1, 1000);

    if (rv == 0) 
    {
      config->status = HPFEEDS_READY;
      SCLogNotice("alert-hpfeeds: Initial publish done.\n");
    }
    else if (rv > 0 && config->pfd.revents && POLLIN) 
    {
          
      config->status = HPFEEDS_NOK;    
      hpf_msg_t *error_msg = NULL;

      if ((error_msg = (hpf_msg_t *) HPFeedsReadMsg(config->sock)) != NULL) 
      {
        HPFeedsGetError(error_msg, config->sock);
        SCLogNotice("alert-hpfeeds: Failed to publish.\n");
      }
      else 
      {
        SCLogNotice("alert-hpfeeds: Something went wrong\n");
      }

       HPFeedsCloseConnection(&config->sock);
    } 
  }

  free(data);
  hpf_msg_delete(msg);
}

#endif /* !OS_WIN32 */



/** \brief   Function to register the AlertHPFeed module */
void AlertHPFeeds(void)
{
#ifndef OS_WIN32

    tmm_modules[TMM_ALERTHPFEEDS].name = MODULE_NAME;
    tmm_modules[TMM_ALERTHPFEEDS].ThreadInit = AlertHPFeedsThreadInit;
    tmm_modules[TMM_ALERTHPFEEDS].Func = NULL;
    tmm_modules[TMM_ALERTHPFEEDS].ThreadDeinit = AlertHPFeedsThreadDeinit;
    tmm_modules[TMM_ALERTHPFEEDS].cap_flags = 0;
    tmm_modules[TMM_ALERTHPFEEDS].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(LOGGER_HPFEEDS, MODULE_NAME, "alert-hpfeeds",
        AlertHPFeedsInitCtx, AlertHPFeedsLogger, AlertHPFeedsCondition, AlertHPFeedsThreadInit, AlertHPFeedsThreadDeinit, NULL);

#endif /* !OS_WIN32 */
}
