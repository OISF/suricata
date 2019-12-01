/* Copyright (C) 2014-2019 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 *
 *  Netfilter's netfilter_log support
 */
#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "tm-queuehandlers.h"
#include "tmqh-packetpool.h"

#include "runmodes.h"
#include "util-error.h"
#include "util-device.h"

#ifndef HAVE_NFLOG
/** Handle the case where no NFLOG support is compiled in.
 *
 */

TmEcode NoNFLOGSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveNFLOGRegister (void)
{
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = NoNFLOGSupportExit;
}

void TmModuleDecodeNFLOGRegister (void)
{
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = NoNFLOGSupportExit;
}

TmEcode NoNFLOGSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NFLOG_NOSUPPORT,"Error creating thread %s: you do not have support for nflog "
           "enabled please recompile with --enable-nflog", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have NFLOG support */

#include "source-nflog.h"

TmEcode ReceiveNFLOGThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveNFLOGLoop(ThreadVars *, void *, void *);
void ReceiveNFLOGThreadExitStats(ThreadVars *, void *);

TmEcode DecodeNFLOGThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeNFLOGThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeNFLOG(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

static int runmode_workers;

/* Structure to hold thread specific variables */
typedef struct NFLOGThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;

    char *data;
    int datalen;

    uint16_t group;
    uint32_t nlbufsiz;
    uint32_t nlbufsiz_max;

    struct mnl_socket *nl;
    struct nlmsghdr *nlh;
    unsigned int portid;

    LiveDevice *livedev;
    int nful_overrun_warned;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
} NFLOGThreadVars;

/**
 * \brief Registration function for ReceiveNFLOG
 */
void TmModuleReceiveNFLOGRegister (void)
{
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = ReceiveNFLOGThreadInit;
    tmm_modules[TMM_RECEIVENFLOG].Func = NULL;
    tmm_modules[TMM_RECEIVENFLOG].PktAcqLoop = ReceiveNFLOGLoop;
    tmm_modules[TMM_RECEIVENFLOG].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENFLOG].ThreadExitPrintStats = ReceiveNFLOGThreadExitStats;
    tmm_modules[TMM_RECEIVENFLOG].ThreadDeinit = ReceiveNFLOGThreadDeinit;
    tmm_modules[TMM_RECEIVENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFLOG].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration function for DecodeNFLOG
 */
void TmModuleDecodeNFLOGRegister (void)
{
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = DecodeNFLOGThreadInit;
    tmm_modules[TMM_DECODENFLOG].Func = DecodeNFLOG;
    tmm_modules[TMM_DECODENFLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFLOG].ThreadDeinit = DecodeNFLOGThreadDeinit;
    tmm_modules[TMM_DECODENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFLOG].flags = TM_FLAG_DECODE_TM;
}

static struct nlmsghdr *
nflog_build_cfg_pf_request(char *buf, uint8_t command)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;

	struct nfulnl_msg_config_cmd cmd = {
		.command = command,
	};
	mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(cmd), &cmd);

	return nlh;
}

static struct nlmsghdr *
nflog_build_cfg_request(char *buf, uint8_t command, int qnum)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(qnum);

	struct nfulnl_msg_config_cmd cmd = {
		.command = command,
	};
	mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(cmd), &cmd);

	return nlh;
}

static struct nlmsghdr *
nflog_build_cfg_params(char *buf, uint8_t mode, int range, int qnum)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(qnum);

	struct nfulnl_msg_config_mode params = {
		.copy_range = htonl(range),
		.copy_mode = mode,
	};
	mnl_attr_put(nlh, NFULA_CFG_MODE, sizeof(params), &params);

	return nlh;
}

static int nflog_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NFULA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFULA_MARK:
	case NFULA_IFINDEX_INDEV:
	case NFULA_IFINDEX_OUTDEV:
	case NFULA_IFINDEX_PHYSINDEV:
	case NFULA_IFINDEX_PHYSOUTDEV:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_TIMESTAMP:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_timestamp)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_HWADDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_hw)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_PREFIX:
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_PAYLOAD:
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/**
 * \brief NFLOG callback function
 * This function setup a packet from a nflog message
 */
static int NFLOGCallback(const struct nlmsghdr *nlh, void *data)
{
    NFLOGThreadVars *ntv = (NFLOGThreadVars *) data;
    if (ntv == NULL) {
        return MNL_CB_ERROR;
    }
    struct nlattr *tb[NFULA_MAX+1] = {};
    struct nfulnl_msg_packet_hdr *ph;
    char *payload;
    uint32_t payload_len;

    /* grab a packet*/
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL)
        return MNL_CB_ERROR;

    PKT_SET_SRC(p, PKT_SRC_WIRE);

    mnl_attr_parse(nlh, sizeof(struct nfgenmsg), nflog_parse_attr_cb, tb);
    if (tb[NFULA_PACKET_HDR]) {
        ph = mnl_attr_get_payload(tb[NFULA_PACKET_HDR]);
        p->nflog_v.hw_protocol = ph->hw_protocol;
    }
    if (tb[NFULA_IFINDEX_INDEV]) {
        p->nflog_v.ifi = mnl_attr_get_u32(tb[NFULA_IFINDEX_INDEV]);
    }
    if (tb[NFULA_IFINDEX_OUTDEV]) {
        p->nflog_v.ifi = mnl_attr_get_u32(tb[NFULA_IFINDEX_OUTDEV]);
    }
    payload_len = mnl_attr_get_payload_len(tb[NFULA_PAYLOAD]);
    payload = mnl_attr_get_payload(tb[NFULA_PAYLOAD]);
    if (payload_len > 0) {
        if (payload_len > 65536) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "NFLOG sent too big packet");
            SET_PKT_LEN(p, 0);
        } else if (runmode_workers)
            PacketSetData(p, (uint8_t *)payload, payload_len);
        else
            PacketCopyData(p, (uint8_t *)payload, payload_len);
    } else
        SET_PKT_LEN(p, 0);

    memset(&p->ts, 0, sizeof(struct timeval));
    gettimeofday(&p->ts, NULL);

    p->datalink = DLT_RAW;

#ifdef COUNTERS
    ntv->pkts++;
    ntv->bytes += GET_PKT_LEN(p);
#endif
    (void) SC_ATOMIC_ADD(ntv->livedev->pkts, 1);

    if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ntv->tv, p);
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

/**
 * \brief Receives packet from a nflog group via libnetfilter_log
 * This is a setup function for recieving packets via libnetfilter_log.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the group passed from the user
 * \param data pointer gets populated with NFLOGThreadVars
 * \retvalTM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on error
 */
TmEcode ReceiveNFLOGThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    NflogGroupConfig *nflconfig = (NflogGroupConfig *)initdata;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NFLOGThreadVars *ntv = SCMalloc(sizeof(NFLOGThreadVars));
    if (unlikely(ntv == NULL)) {
        nflconfig->DerefFunc(nflconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ntv, 0, sizeof(NFLOGThreadVars));

    ntv->tv = tv;
    ntv->group = nflconfig->group;
    ntv->nlbufsiz = nflconfig->nlbufsiz;
    ntv->nlbufsiz_max = nflconfig->nlbufsiz_max;
    ntv->nful_overrun_warned = nflconfig->nful_overrun_warned;

    ntv->nl = mnl_socket_open(NETLINK_NETFILTER);
    if (ntv->nl == NULL) {
        SCLogError(SC_ERR_MNL_OPEN, "mnl_socket_open() failed");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(ntv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        SCLogError(SC_ERR_MNL_BIND, "mnl_socket_bind() failed");
        exit(EXIT_FAILURE);
    }
    ntv->portid = mnl_socket_get_portid(ntv->nl);

    ntv->nlh = nflog_build_cfg_pf_request(buf, NFULNL_CFG_CMD_PF_BIND);
    if (mnl_socket_sendto(ntv->nl, ntv->nlh, ntv->nlh->nlmsg_len) < 0) {
        SCLogError(SC_ERR_MNL_SENDTO, "nflog_build_cfg_pf_request() failed");
        return TM_ECODE_FAILED;
    }

    ntv->nlh = nflog_build_cfg_request(buf, NFULNL_CFG_CMD_BIND, ntv->group);
    if (mnl_socket_sendto(ntv->nl, ntv->nlh, ntv->nlh->nlmsg_len) < 0) {
        SCLogError(SC_ERR_MNL_SENDTO, "nflog_build_cfg_request() failed");
        return TM_ECODE_FAILED;
    }

    ntv->nlh = nflog_build_cfg_params(buf, NFULNL_COPY_PACKET, 0xFFFF, ntv->group);
    if (mnl_socket_sendto(ntv->nl, ntv->nlh, ntv->nlh->nlmsg_len) < 0) {
        SCLogError(SC_ERR_MNL_SENDTO, "can't sent packet copy mode");
        return TM_ECODE_FAILED;
    }

    setsockopt(mnl_socket_get_fd(ntv->nl), SOL_SOCKET, SO_RCVBUFFORCE,
              &ntv->nlbufsiz, sizeof(socklen_t));

    ntv->livedev = LiveGetDevice(nflconfig->numgroup);
    if (ntv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    struct timeval timev;
    timev.tv_sec = 1;
    timev.tv_usec = 0;

    if (setsockopt(mnl_socket_get_fd(ntv->nl), SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        SCLogWarning(SC_WARN_NFLOG_SETSOCKOPT, "can't set socket "
                "timeout: %s", strerror(errno));
    }

#ifdef PACKET_STATISTICS
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
                                                       ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
                                                     ntv->tv);
#endif

    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode))
        runmode_workers = 1;
    else
        runmode_workers = 0;

#define T_DATA_SIZE 70000
    ntv->data = SCMalloc(T_DATA_SIZE);
    if (ntv->data == NULL) {
        nflconfig->DerefFunc(nflconfig);
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ntv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    *data = (void *)ntv;

    nflconfig->DerefFunc(nflconfig);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief DeInit function unbind group and close nflog's handle
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLogThreadVars
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *tv, void *data)
{
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    SCLogDebug("closing nflog group %d", ntv->group);
    ntv->nlh = nflog_build_cfg_pf_request(buf, NFULNL_CFG_CMD_PF_UNBIND);
    if (mnl_socket_sendto(ntv->nl, ntv->nlh, ntv->nlh->nlmsg_len) < 0) {
        SCLogError(SC_ERR_MNL_SENDTO, "nflog_build_cfg_pf_request() failed");
        exit(EXIT_FAILURE);
    }

    if (ntv->nl) {
        mnl_socket_close(ntv->nl);
        ntv->nl = NULL;
    }

    if (ntv->data != NULL) {
        SCFree(ntv->data);
        ntv->data = NULL;
    }
    ntv->datalen = 0;

    SCFree(ntv);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Increases netlink buffer size
 *
 * This function netlink's buffer size until
 * the max buffer size is reached
 *
 * \param data pointer that gets cast into NFLOGThreadVars
 * \param size netlink buffer size
 */
static int NFLOGSetnlbufsiz(void *data)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    if (ntv->nlbufsiz < ntv->nlbufsiz_max) {
        setsockopt(mnl_socket_get_fd(ntv->nl), SOL_SOCKET, SO_RCVBUFFORCE,
                   &ntv->nlbufsiz, sizeof(socklen_t));
        return 1;
    }

    SCLogWarning(SC_WARN_NFLOG_MAXBUFSIZ_REACHED,
                 "Maximum buffer size (%d) in NFLOG has been "
                 "reached. Please, consider raising "
                 "`buffer-size` and `max-size` in nflog configuration",
                 ntv->nlbufsiz_max);
    return 0;

}

/**
 * \brief Recieves packets from a group via libnetfilter_log.
 *
 *  This function recieves packets from a group and passes
 *  the packet on to the nflog callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLOGThreadVars
 * \param slot slot containing task information
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode ReceiveNFLOGLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;
    int rv;
    int ret = -1;

    ntv->slot = ((TmSlot *) slot)->slot_next;

    while (1) {
        if (suricata_ctl_flags != 0)
            break;

        rv = mnl_socket_recvfrom(ntv->nl, ntv->data, ntv->datalen);
        if (rv < 0) {
            /*We received an error on socket read */
            if (errno == EINTR || errno == EWOULDBLOCK) {
                /*Nothing for us to process */
                continue;
            } else if (errno == ENOBUFS) {
                if (!ntv->nful_overrun_warned) {
                    ntv->nlbufsiz *= 2;
                    if (NFLOGSetnlbufsiz((void *)ntv)) {
                        SCLogWarning(SC_WARN_NFLOG_LOSING_EVENTS,
                                "We are losing events, "
                                "increasing buffer size "
                                "to %d", ntv->nlbufsiz);
                    } else {
                        ntv->nful_overrun_warned = 1;
                    }
                }
                continue;
            } else {
                SCLogWarning(SC_WARN_MNL_RECVFROM,
                             "Read from NFLOG fd failed: %s",
                             strerror(errno));
                SCReturnInt(TM_ECODE_FAILED);
            }
        }

        ret = mnl_cb_run(ntv->data, rv, 0, ntv->portid, NFLOGCallback, (void *)ntv);
        if (ret == -1)
            SCLogWarning(SC_ERR_MNL_CB,
                         "mnl_cb_run() failed: %s", strerror(errno));

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLOGThreadVars
 */
void ReceiveNFLOGThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    SCLogNotice("(%s) Pkts %" PRIu32 ", Bytes %" PRIu64 "",
                 tv->name, ntv->pkts, ntv->bytes);
}


/**
 * \brief Decode IPv4/v6 packets.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into NFLOGThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodeNFLOG(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    DecodeUpdatePacketCounters(tv, dtv, p);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else {
        SCLogDebug("packet unsupported by NFLOG, first byte: %02x", *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This an Init function for DecodeNFLOG
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to initilization data.
 * \param data pointer that gets cast into NFLOGThreadVars
 * \retval TM_ECODE_OK is returned on success
 * \retval TM_ECODE_FAILED is returned on error
 */
TmEcode DecodeNFLOGThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeNFLOGThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* NFLOG */
