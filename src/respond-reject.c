/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author William Metcalf <william.metcalf@gmail.com>
 *
 * RespondReject is a threaded wrapper for sending Rejects
 *
 * \todo RespondRejectFunc returns 1 on error, 0 on ok... why? For now it should
 *   just return 0 always, error handling is a TODO in the threading model (VJ)
 */

#include "suricata-common.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "action-globals.h"

#include "respond-reject.h"
#include "respond-reject-libnet11.h"

#include "util-debug.h"
#include "util-privs.h"

#include <net/if.h>

int RejectSendIPv4TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv4ICMP(ThreadVars *, Packet *, void *);
int RejectSendIPv6TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv6ICMP(ThreadVars *, Packet *, void *);

static TmEcode RespondRejectInit(ThreadVars *tv, const void *initdata, void **data);

typedef struct RespondRejectThread_ {
    int force_iface;
    char devname[IFNAMSIZ];
} RespondRejectThread;

void TmModuleRespondRejectRegister (void)
{
    tmm_modules[TMM_RESPONDREJECT].name = "RespondReject";
    tmm_modules[TMM_RESPONDREJECT].ThreadInit = RespondRejectInit;
    tmm_modules[TMM_RESPONDREJECT].Func = RespondRejectFunc;
    tmm_modules[TMM_RESPONDREJECT].ThreadDeinit = NULL;
    tmm_modules[TMM_RESPONDREJECT].RegisterTests = NULL;
    tmm_modules[TMM_RESPONDREJECT].cap_flags = 0; /* libnet is not compat with caps */
}

TmEcode RespondRejectFunc(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    int ret = 0;

    /* ACTION_REJECT defaults to rejecting the SRC */
    if (!(PACKET_TEST_ACTION(p, ACTION_REJECT)) &&
        !(PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) &&
        !(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH))) {
        return TM_ECODE_OK;
    }

    if (PKT_IS_IPV4(p)) {
        if (PKT_IS_TCP(p)) {
            ret = RejectSendIPv4TCP(tv, p, data);
        } else {
            ret = RejectSendIPv4ICMP(tv, p, data);
        }
    } else if (PKT_IS_IPV6(p)) {
        if (PKT_IS_TCP(p)) {
            ret = RejectSendIPv6TCP(tv, p, data);
        } else {
            ret = RejectSendIPv6ICMP(tv, p, data);
        }
    } else {
        /* we're only supporting IPv4 and IPv6 */
        return TM_ECODE_OK;
    }

    if (ret)
        return TM_ECODE_FAILED;
    else
        return TM_ECODE_OK;
}


static TmEcode RespondRejectInit(ThreadVars *tv, const void *initdata, void **data)
{
    RespondRejectThread *rrt = SCMalloc(sizeof(RespondRejectThread));
    if (unlikely(rrt == NULL))
        return TM_ECODE_FAILED;

    rrt->force_iface = 0;

    /* Get the iface name */
    const char *conf_val;
    if ((ConfGetValue("reject-iface", &conf_val)) == 1) {
        if (strlen(conf_val) >= IFNAMSIZ) {
            SCLogError(SC_ERR_INVALID_VALUE, "Interface name too long");
        } else {
            strlcpy(rrt->devname, conf_val, IFNAMSIZ);
            rrt->force_iface = 1;
            SCLogInfo("Sending reject packets to interface '%s'", conf_val);
        }
    }

    return TM_ECODE_OK;
}

int RejectSendIPv4TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    RespondRejectThread *rrt = (RespondRejectThread *)tv;
    int r = 0;
    const char* devname = NULL;
    if (rrt->force_iface) {
        devname = rrt->devname;
    }
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC, devname);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST, devname);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC, devname);
        if (RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST, devname) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv4ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    RespondRejectThread *rrt = (RespondRejectThread *)tv;
    int r = 0;
    const char* devname = NULL;
    if (rrt->force_iface) {
        devname = rrt->devname;
    }
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_SRC, devname);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_DST, devname);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_SRC, devname);
        if (RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_DST, devname) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv6TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    RespondRejectThread *rrt = (RespondRejectThread *)tv;
    int r = 0;
    const char* devname = NULL;
    if (rrt->force_iface) {
        devname = rrt->devname;
    }
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_SRC, devname);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_DST, devname);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_SRC, devname);
        if (RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_DST, devname) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv6ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    RespondRejectThread *rrt = (RespondRejectThread *)tv;
    int r = 0;
    const char* devname = NULL;
    if (rrt->force_iface) {
        devname = rrt->devname;
    }
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_SRC, devname);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_DST, devname);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_SRC, devname);
        if (RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_DST, devname) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

