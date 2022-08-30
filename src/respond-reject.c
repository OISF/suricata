/* Copyright (C) 2007-2022 Open Information Security Foundation
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

int RejectSendIPv4TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv4ICMP(ThreadVars *, Packet *, void *);
int RejectSendIPv6TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv6ICMP(ThreadVars *, Packet *, void *);
static TmEcode RespondRejectFunc(ThreadVars *tv, Packet *p, void *data);
static TmEcode RespondRejectThreadDeinit(ThreadVars *tv, void *data);

void TmModuleRespondRejectRegister (void)
{
    tmm_modules[TMM_RESPONDREJECT].name = "RespondReject";
    tmm_modules[TMM_RESPONDREJECT].ThreadInit = NULL;
    tmm_modules[TMM_RESPONDREJECT].Func = RespondRejectFunc;
    tmm_modules[TMM_RESPONDREJECT].ThreadDeinit = RespondRejectThreadDeinit;
    tmm_modules[TMM_RESPONDREJECT].cap_flags = 0; /* libnet is not compat with caps */
}

static TmEcode RespondRejectThreadDeinit(ThreadVars *tv, void *data)
{
    FreeCachedCtx();
    return TM_ECODE_OK;
}

static TmEcode RespondRejectFunc(ThreadVars *tv, Packet *p, void *data)
{
    /* ACTION_REJECT defaults to rejecting the SRC */
    if (likely(PacketTestAction(p, ACTION_REJECT_ANY) == 0)) {
        return TM_ECODE_OK;
    }

    if (IS_TUNNEL_PKT(p)) {
        return TM_ECODE_OK;
    }

    if (PKT_IS_IPV4(p)) {
        if (PKT_IS_TCP(p)) {
            (void)RejectSendIPv4TCP(tv, p, data);
        } else {
            (void)RejectSendIPv4ICMP(tv, p, data);
        }
    } else if (PKT_IS_IPV6(p)) {
        if (PKT_IS_TCP(p)) {
            (void)RejectSendIPv6TCP(tv, p, data);
        } else {
            (void)RejectSendIPv6ICMP(tv, p, data);
        }
    }

    return TM_ECODE_OK;
}

int RejectSendIPv4TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    if (PacketTestAction(p, ACTION_REJECT)) {
        int r = RejectSendLibnet11IPv4TCP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_DST)) {
        int r = RejectSendLibnet11IPv4TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_BOTH)) {
        int r = RejectSendLibnet11IPv4TCP(tv, p, data, REJECT_DIR_SRC);
        r |= RejectSendLibnet11IPv4TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    }
    SCReturnInt(0);
}

int RejectSendIPv4ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    if (PacketTestAction(p, ACTION_REJECT)) {
        int r = RejectSendLibnet11IPv4ICMP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_DST)) {
        int r = RejectSendLibnet11IPv4ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_BOTH)) {
        int r = RejectSendLibnet11IPv4ICMP(tv, p, data, REJECT_DIR_SRC);
        r |= RejectSendLibnet11IPv4ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    }
    SCReturnInt(0);
}

int RejectSendIPv6TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    if (PacketTestAction(p, ACTION_REJECT)) {
        int r = RejectSendLibnet11IPv6TCP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_DST)) {
        int r = RejectSendLibnet11IPv6TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_BOTH)) {
        int r = RejectSendLibnet11IPv6TCP(tv, p, data, REJECT_DIR_SRC);
        r |= RejectSendLibnet11IPv6TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    }
    SCReturnInt(0);
}

int RejectSendIPv6ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    if (PacketTestAction(p, ACTION_REJECT)) {
        int r = RejectSendLibnet11IPv6ICMP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_DST)) {
        int r = RejectSendLibnet11IPv6ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if (PacketTestAction(p, ACTION_REJECT_BOTH)) {
        int r = RejectSendLibnet11IPv6ICMP(tv, p, data, REJECT_DIR_SRC);
        r |= RejectSendLibnet11IPv6ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    }
    SCReturnInt(0);
}
