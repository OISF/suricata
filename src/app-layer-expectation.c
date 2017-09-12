/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#include "suricata-common.h"
#include "debug.h"

#include "ippair-storage.h"

#include "app-layer-expectation.h"

static int g_expectation_id = -1;

/* FIXME we need a list here */
typedef struct Expectation_ {
    struct timeval ts;
    Port sp;
    Port dp;
    AppProto alproto;
} Expectation;

static void ExpectationFree(void *e)
{
    SCFree(e);
}

void AppLayerExpectationSetup(void)
{
    g_expectation_id = IPPairStorageRegister("ttl", sizeof(void *), NULL, ExpectationFree);
}

static inline int GetFlowAddresses(Flow *f, Address *ip_src, Address *ip_dst)
{
    if (FLOW_IS_IPV4(f)) {
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else if (FLOW_IS_IPV6(f)) {
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else {
        return -1;
    }
    return 0;
}

int AppLayerExpectationCreate(Flow *f, int direction, Port src, Port dst, AppProto alproto)
{
    IPPair *ipp;

    Expectation *exp = SCCalloc(1, sizeof(*exp));
    if (exp == NULL)
        return -1;

    exp->sp = src;
    exp->dp = dst;
    exp->alproto = alproto;
    exp->ts = f->lastts;

    Address ip_src, ip_dst;
    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return -1;
    if (direction & STREAM_TOSERVER) {
        ipp = IPPairGetIPPairFromHash(&ip_src, &ip_dst);
    } else {
        ipp = IPPairGetIPPairFromHash(&ip_dst, &ip_src);
    }
    if (ipp == NULL)
        return -1;

    /* FIXME check if existing and use linked list */
    IPPairSetStorageById(ipp, g_expectation_id, exp);

    IPPairUnlock(ipp);
    return 0;
}

static Expectation *AppLayerExpectationGet(Flow *f, int direction, IPPair **ipp)
{
    Address ip_src, ip_dst;
    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return NULL;
    if (direction & STREAM_TOSERVER) {
        *ipp = IPPairLookupIPPairFromHash(&ip_src, &ip_dst);
    } else {
        *ipp = IPPairLookupIPPairFromHash(&ip_dst, &ip_src);
    }
    if (*ipp == NULL)
        return NULL;

    return IPPairGetStorageById(*ipp, g_expectation_id);
}

AppProto AppLayerExpectationLookup(Flow *f, int direction)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    IPPair *ipp = NULL;

    Expectation *exp = AppLayerExpectationGet(f, direction, &ipp);

    if (exp == NULL)
        goto out;

    /* FIXME direction */
    if ((exp->sp == 0) || (exp->sp == f->sp)) {
        if ((exp->dp == 0) || (exp->dp == f->dp)) {
            /* FIXME timestamp and cleaning */
            alproto = exp->alproto;
        }
    }

out:
    if (ipp)
        IPPairUnlock(ipp);
    return alproto;
}
