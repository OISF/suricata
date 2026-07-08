/* Copyright (C) 2026 Open Information Security Foundation
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

/** \file \brief tcp.session: keyword (Redmine #7704). */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "flow.h"
#include "stream-tcp.h"
#include "stream-tcp-private.h"

#include "util-debug.h"
#include "util-unittest.h"

#include "detect-tcp-session.h"

/** Upper bound on the total length of the keyword argument. */
#define DETECT_TCP_SESSION_ARG_MAX_LEN 32

/* prototypes */
static int DetectTcpSessionMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectTcpSessionSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTcpSessionFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectTcpSessionRegisterTests(void);
#endif

/** Map a single phase token to its phase flag. */
static uint8_t DetectTcpSessionPhaseFlagFromToken(const char *token, size_t len)
{
    if (len == 5 && memcmp(token, "setup", 5) == 0) {
        return DETECT_TCP_SESSION_PHASE_SETUP;
    }
    if (len == 11 && memcmp(token, "established", 11) == 0) {
        return DETECT_TCP_SESSION_PHASE_ESTABLISHED;
    }
    if (len == 7 && memcmp(token, "closing", 7) == 0) {
        return DETECT_TCP_SESSION_PHASE_CLOSING;
    }
    return 0;
}

/** Parse a tcp.session: keyword argument into a DetectTcpSessionData. */
static DetectTcpSessionData *DetectTcpSessionParse(const char *arg)
{
    if (arg == NULL) {
        SCLogError("tcp.session keyword requires a value: comma-separated "
                   "subset of {setup, established, closing}");
        return NULL;
    }

    const size_t arglen = strlen(arg);

    if (arglen == 0) {
        SCLogError("tcp.session keyword requires a value: comma-separated "
                   "subset of {setup, established, closing}");
        return NULL;
    }

    if (arglen > DETECT_TCP_SESSION_ARG_MAX_LEN) {
        SCLogError("tcp.session argument too long (%zu > %d): accepted "
                   "tokens are {setup, established, closing}",
                arglen, DETECT_TCP_SESSION_ARG_MAX_LEN);
        return NULL;
    }

    uint8_t phase_flags = 0;

    /* Split on ',' and validate each token. */
    size_t token_start = 0;
    for (size_t i = 0; i <= arglen; i++) {
        if (i != arglen && arg[i] != ',') {
            continue;
        }

        const size_t token_len = i - token_start;
        const char *token = arg + token_start;

        if (token_len == 0) {
            SCLogError("tcp.session: empty token in argument \"%s\"; "
                       "accepted tokens are {setup, established, closing}",
                    arg);
            return NULL;
        }

        const uint8_t flag = DetectTcpSessionPhaseFlagFromToken(token, token_len);
        if (flag == 0) {
            SCLogError("tcp.session: unknown token \"%.*s\" in argument "
                       "\"%s\"; accepted tokens are {setup, established, "
                       "closing}",
                    (int)token_len, token, arg);
            return NULL;
        }

        if (phase_flags & flag) {
            SCLogError("tcp.session: duplicate token \"%.*s\" in argument "
                       "\"%s\"; accepted tokens are {setup, established, "
                       "closing}",
                    (int)token_len, token, arg);
            return NULL;
        }

        phase_flags |= flag;
        token_start = i + 1;
    }

    if (phase_flags == 0) {
        SCLogError("tcp.session keyword requires a value: comma-separated "
                   "subset of {setup, established, closing}");
        return NULL;
    }

    DetectTcpSessionData *data = SCMalloc(sizeof(*data));
    if (unlikely(data == NULL)) {
        return NULL;
    }
    data->phase_flags = phase_flags;
    return data;
}

/** Per-packet match: returns 1 iff the packet's TCP session phase intersects phase_flags. */
static int DetectTcpSessionMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectTcpSessionData *d = (const DetectTcpSessionData *)ctx;
    const Flow *f = p->flow;

    if (f == NULL || f->proto != IPPROTO_TCP) {
        return 0;
    }

    uint8_t pkt_phase = 0;

    /* Setup vs established split via FLOW_PKT_ESTABLISHED. */
    if (p->flowflags & FLOW_PKT_ESTABLISHED) {
        pkt_phase |= DETECT_TCP_SESSION_PHASE_ESTABLISHED;
    } else {
        pkt_phase |= DETECT_TCP_SESSION_PHASE_SETUP;
    }

    /* Closing phase: consult TcpSession::state directly. */
    const TcpSession *ssn = (const TcpSession *)f->protoctx;
    if (ssn != NULL) {
        switch (ssn->state) {
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
            case TCP_TIME_WAIT:
            case TCP_LAST_ACK:
            case TCP_CLOSE_WAIT:
            case TCP_CLOSING:
                pkt_phase |= DETECT_TCP_SESSION_PHASE_CLOSING;
                break;
            default:
                break;
        }
    }

    return (pkt_phase & d->phase_flags) ? 1 : 0;
}

/** Setup function: parse argument and append the SigMatch. */
static int DetectTcpSessionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (!(DetectProtoContainsProto(&s->init_data->proto, IPPROTO_TCP))) {
        SCLogError("tcp.session requires a TCP rule");
        return -1;
    }

    DetectTcpSessionData *data = DetectTcpSessionParse(arg);
    if (data == NULL) {
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_TCP_SESSION, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) == NULL) {
        DetectTcpSessionFree(de_ctx, data);
        return -1;
    }

    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/** Free a DetectTcpSessionData allocation. */
static void DetectTcpSessionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

/** Registration function for the tcp.session: keyword. */
void DetectTcpSessionRegister(void)
{
    sigmatch_table[DETECT_TCP_SESSION].name = "tcp.session";
    sigmatch_table[DETECT_TCP_SESSION].desc =
            "match TCP session lifecycle phase set (setup, established, closing)";
    sigmatch_table[DETECT_TCP_SESSION].url = "/rules/flow-keywords.html#tcp-session";
    sigmatch_table[DETECT_TCP_SESSION].Match = DetectTcpSessionMatch;
    sigmatch_table[DETECT_TCP_SESSION].Setup = DetectTcpSessionSetup;
    sigmatch_table[DETECT_TCP_SESSION].Free = DetectTcpSessionFree;
    sigmatch_table[DETECT_TCP_SESSION].flags = SIGMATCH_SUPPORT_FIREWALL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TCP_SESSION].RegisterTests = DetectTcpSessionRegisterTests;
#endif
}

#ifdef UNITTESTS
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "detect-engine.h"
#include "detect-flow.h"

int DetectFlowMatch(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);

/** Test01: single-token parsing. */
static int DetectTcpSessionTest01(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("setup");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_SETUP);
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("established");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_ESTABLISHED);
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_CLOSING);
    DetectTcpSessionFree(NULL, d);

    PASS;
}

/** Test02: multi-token parsing and order independence. */
static int DetectTcpSessionTest02(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("setup,established");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED));
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("established,setup");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED));
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("setup,established,closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED |
                        DETECT_TCP_SESSION_PHASE_CLOSING));
    DetectTcpSessionFree(NULL, d);

    PASS;
}

/** Test03: closing token and closing combinations. */
static int DetectTcpSessionTest03(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_CLOSING);
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("established,closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_ESTABLISHED | DETECT_TCP_SESSION_PHASE_CLOSING));
    DetectTcpSessionFree(NULL, d);

    PASS;
}

/** Test04: empty/missing value is rejected. */
static int DetectTcpSessionTest04(void)
{
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(NULL));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(""));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(","));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(",setup"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,,established"));
    PASS;
}

/** Test05: unknown/whitespace/over-length tokens are rejected. */
static int DetectTcpSessionTest05(void)
{
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("bogus"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,bogus"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("SETUP"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(" setup"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup "));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setu p"));
    char longarg[128];
    memset(longarg, 'a', sizeof(longarg) - 1);
    longarg[sizeof(longarg) - 1] = '\0';
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(longarg));
    PASS;
}

/** Test06: duplicate tokens are rejected. */
static int DetectTcpSessionTest06(void)
{
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,setup"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("established,established"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,established,setup"));
    PASS;
}

/** Build a minimal TCP packet+flow harness for match tests. */
static Packet *DetectTcpSessionTestBuildPacket(
        Flow *f, TcpSession *ssn, TCPHdr *tcph, uint8_t state, bool established)
{
    Packet *p = PacketGetFromAlloc();
    if (p == NULL)
        return NULL;

    memset(f, 0, sizeof(*f));
    memset(ssn, 0, sizeof(*ssn));
    memset(tcph, 0, sizeof(*tcph));

    f->proto = IPPROTO_TCP;
    ssn->state = state;
    f->protoctx = ssn;

    p->flow = f;
    PacketSetTCP(p, (uint8_t *)tcph);
    p->flowflags |= FLOW_PKT_TOSERVER;
    if (established) {
        p->flowflags |= FLOW_PKT_ESTABLISHED;
    }
    return p;
}

/** Test07: established flow matches tcp.session:established. */
static int DetectTcpSessionTest07(void)
{
    Flow f;
    TcpSession ssn;
    TCPHdr tcph;
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Signature s;
    memset(&tv, 0, sizeof(tv));
    memset(&dtx, 0, sizeof(dtx));
    memset(&s, 0, sizeof(s));

    Packet *p = DetectTcpSessionTestBuildPacket(&f, &ssn, &tcph, TCP_ESTABLISHED, true);
    FAIL_IF_NULL(p);

    DetectTcpSessionData *d = DetectTcpSessionParse("established");
    FAIL_IF_NULL(d);

    FAIL_IF_NOT(DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)d) == 1);

    DetectTcpSessionFree(NULL, d);
    PacketFree(p);
    PASS;
}

/** Test08: SYN_SENT flow matches tcp.session:setup but not established. */
static int DetectTcpSessionTest08(void)
{
    Flow f;
    TcpSession ssn;
    TCPHdr tcph;
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Signature s;
    memset(&tv, 0, sizeof(tv));
    memset(&dtx, 0, sizeof(dtx));
    memset(&s, 0, sizeof(s));

    Packet *p = DetectTcpSessionTestBuildPacket(&f, &ssn, &tcph, TCP_SYN_SENT, false);
    FAIL_IF_NULL(p);

    DetectTcpSessionData *setup = DetectTcpSessionParse("setup");
    FAIL_IF_NULL(setup);
    FAIL_IF_NOT(DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)setup) == 1);
    DetectTcpSessionFree(NULL, setup);

    DetectTcpSessionData *est = DetectTcpSessionParse("established");
    FAIL_IF_NULL(est);
    FAIL_IF_NOT(DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)est) == 0);
    DetectTcpSessionFree(NULL, est);

    PacketFree(p);
    PASS;
}

/** Test09: midstream pickup in TCP_ESTABLISHED matches established, not setup. */
static int DetectTcpSessionTest09(void)
{
    Flow f;
    TcpSession ssn;
    TCPHdr tcph;
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Signature s;
    memset(&tv, 0, sizeof(tv));
    memset(&dtx, 0, sizeof(dtx));
    memset(&s, 0, sizeof(s));

    Packet *p = DetectTcpSessionTestBuildPacket(&f, &ssn, &tcph, TCP_ESTABLISHED, true);
    FAIL_IF_NULL(p);
    ssn.flags |= STREAMTCP_FLAG_MIDSTREAM | STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;

    DetectTcpSessionData *est = DetectTcpSessionParse("established");
    FAIL_IF_NULL(est);
    FAIL_IF_NOT(DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)est) == 1);
    DetectTcpSessionFree(NULL, est);

    DetectTcpSessionData *setup = DetectTcpSessionParse("setup");
    FAIL_IF_NULL(setup);
    FAIL_IF_NOT(DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)setup) == 0);
    DetectTcpSessionFree(NULL, setup);

    PacketFree(p);
    PASS;
}

/** Test10: equivalence with flow:established / flow:not_established. */
static int DetectTcpSessionTest10(void)
{
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Signature s;
    memset(&tv, 0, sizeof(tv));
    memset(&dtx, 0, sizeof(dtx));
    memset(&s, 0, sizeof(s));

    DetectTcpSessionData *ts_setup = DetectTcpSessionParse("setup");
    FAIL_IF_NULL(ts_setup);
    DetectTcpSessionData *ts_est = DetectTcpSessionParse("established");
    FAIL_IF_NULL(ts_est);

    DetectFlowData fd_not_est = { .flags = DETECT_FLOW_FLAG_NOT_ESTABLISHED, .match_cnt = 1 };
    DetectFlowData fd_est = { .flags = DETECT_FLOW_FLAG_ESTABLISHED, .match_cnt = 1 };

    const uint8_t states[] = { TCP_NONE, TCP_SYN_SENT, TCP_SYN_RECV, TCP_ESTABLISHED };
    const bool est_flags[] = { false, true };

    for (size_t si = 0; si < sizeof(states) / sizeof(states[0]); si++) {
        for (size_t ei = 0; ei < sizeof(est_flags) / sizeof(est_flags[0]); ei++) {
            Flow f;
            TcpSession ssn;
            TCPHdr tcph;
            Packet *p = DetectTcpSessionTestBuildPacket(&f, &ssn, &tcph, states[si], est_flags[ei]);
            FAIL_IF_NULL(p);

            int ts_setup_r = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)ts_setup);
            int flow_not_est_r = DetectFlowMatch(&dtx, p, &s, (const SigMatchCtx *)&fd_not_est);
            FAIL_IF_NOT(ts_setup_r == flow_not_est_r);

            int ts_est_r = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)ts_est);
            int flow_est_r = DetectFlowMatch(&dtx, p, &s, (const SigMatchCtx *)&fd_est);
            FAIL_IF_NOT(ts_est_r == flow_est_r);

            PacketFree(p);
        }
    }

    DetectTcpSessionFree(NULL, ts_setup);
    DetectTcpSessionFree(NULL, ts_est);
    PASS;
}

static int DetectTcpSessionMatchExhaustive(void);

static void DetectTcpSessionRegisterTests(void)
{
    UtRegisterTest("DetectTcpSessionTest01", DetectTcpSessionTest01);
    UtRegisterTest("DetectTcpSessionTest02", DetectTcpSessionTest02);
    UtRegisterTest("DetectTcpSessionTest03", DetectTcpSessionTest03);
    UtRegisterTest("DetectTcpSessionTest04", DetectTcpSessionTest04);
    UtRegisterTest("DetectTcpSessionTest05", DetectTcpSessionTest05);
    UtRegisterTest("DetectTcpSessionTest06", DetectTcpSessionTest06);
    UtRegisterTest("DetectTcpSessionTest07", DetectTcpSessionTest07);
    UtRegisterTest("DetectTcpSessionTest08", DetectTcpSessionTest08);
    UtRegisterTest("DetectTcpSessionTest09", DetectTcpSessionTest09);
    UtRegisterTest("DetectTcpSessionTest10", DetectTcpSessionTest10);
    UtRegisterTest("DetectTcpSessionMatchExhaustive", DetectTcpSessionMatchExhaustive);
}
#endif /* UNITTESTS */

#ifdef UNITTESTS

/** Oracle: compute expected per-packet phase mask from state and flow flag. */
static uint8_t DetectTcpSessionExpectedPhaseMask(enum TcpState state, bool flow_pkt_est)
{
    uint8_t mask = 0;

    if (flow_pkt_est) {
        mask |= DETECT_TCP_SESSION_PHASE_ESTABLISHED;
    } else {
        mask |= DETECT_TCP_SESSION_PHASE_SETUP;
    }

    switch (state) {
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_TIME_WAIT:
        case TCP_LAST_ACK:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
            mask |= DETECT_TCP_SESSION_PHASE_CLOSING;
            break;
        default:
            break;
    }

    return mask;
}

/** Exhaustive match test over all (state × flag × phase_flags) combinations. */
static int DetectTcpSessionMatchExhaustive(void)
{
    /* Iterate all TcpState values (0..TCP_CLOSED). Value 1 is unused
     * (TCP_LISTEN is commented out) but the match function handles it
     * via the default case, so including it is harmless. */

    for (uint8_t st = 0; st <= TCP_CLOSED; st++) {
        for (int est = 0; est <= 1; est++) {
            const bool flow_pkt_est = (est == 1);

            /* All 7 non-empty subsets of the 3-bit phase space. */
            for (uint8_t pf = 1; pf <= 0x7; pf++) {
                ThreadVars tv;
                DetectEngineThreadCtx dtx;
                Signature s;
                TcpSession ssn;
                Flow f;
                Packet *p = PacketGetFromAlloc();
                FAIL_IF_NULL(p);
                memset(&tv, 0, sizeof(tv));
                memset(&dtx, 0, sizeof(dtx));
                memset(&s, 0, sizeof(s));
                memset(&ssn, 0, sizeof(ssn));
                memset(&f, 0, sizeof(f));
                f.proto = IPPROTO_TCP;
                ssn.state = st;
                f.protoctx = &ssn;
                p->flow = &f;
                p->flags |= PKT_HAS_FLOW;
                if (flow_pkt_est)
                    p->flowflags |= FLOW_PKT_ESTABLISHED;

                DetectTcpSessionData d = { .phase_flags = pf };
                const uint8_t expected_mask =
                        DetectTcpSessionExpectedPhaseMask((enum TcpState)st, flow_pkt_est);
                const int expected = (expected_mask & pf) ? 1 : 0;
                const int actual = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)&d);
                PacketFree(p);
                FAIL_IF_NOT(actual == expected);
            }
        }
    }

    PASS;
}

#endif /* UNITTESTS */
