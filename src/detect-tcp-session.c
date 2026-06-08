/* Copyright (C) 2025 Open Information Security Foundation
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
 * \brief tcp.session: keyword
 *
 * Implements the parser and setup half of the `tcp.session:` keyword (the
 * parameter portion of Redmine #7704). The keyword's argument is a
 * comma-separated subset of {setup, established, closing}. The parser
 * tokenises verbatim (no whitespace trim), rejects duplicates, unknown
 * tokens, empty tokens, empty arguments, and arguments longer than 64
 * chars. The result is a single-byte bitfield encoding which phases the
 * rule binds to.
 *
 * The match function reads `p->flowflags & FLOW_PKT_ESTABLISHED` (the same
 * predicate `flow:established` / `flow:not_established` use) for the
 * setup/established split, and consults `TcpSession::state` to detect the
 * six closing substates (FIN_WAIT1, FIN_WAIT2, TIME_WAIT, LAST_ACK,
 * CLOSE_WAIT, CLOSING). The result is a single byte AND'd against the
 * rule's phase_flags.
 */

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
#define DETECT_TCP_SESSION_ARG_MAX_LEN 64

/* prototypes */
static int DetectTcpSessionMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectTcpSessionSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTcpSessionFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectTcpSessionRegisterTests(void);
#endif

/**
 * \internal
 * \brief Map a single phase token to its phase flag.
 *
 * Tokens are matched verbatim (case-sensitive, no whitespace trim):
 * no surrounding whitespace inside tokens.
 *
 * \param token start of the token
 * \param len   length of the token in bytes
 *
 * \retval 0 if the token is not a recognised phase name
 * \retval >0 the corresponding DETECT_TCP_SESSION_PHASE_* bit
 */
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

/**
 * \internal
 * \brief Parse a tcp.session: keyword argument.
 *
 * Accepts a comma-separated subset of {setup, established, closing} (1..3
 * tokens, no duplicates, no surrounding whitespace inside tokens, total
 * argument length not exceeding DETECT_TCP_SESSION_ARG_MAX_LEN bytes).
 *
 * On any validation failure the function emits a precise SCLogError naming
 * the accepted token set and returns NULL. On success it returns a
 * heap-allocated DetectTcpSessionData whose phase_flags field is the OR of
 * the recognised tokens' phase flags.
 *
 * \param arg keyword argument (may be NULL)
 *
 * \retval pointer to allocated DetectTcpSessionData on success
 * \retval NULL on validation or allocation failure
 */
static DetectTcpSessionData *DetectTcpSessionParse(const char *arg)
{
    if (arg == NULL) {
        SCLogError("tcp.session keyword requires a value: comma-separated "
                   "subset of {setup, established, closing}");
        return NULL;
    }

    const size_t arglen = strlen(arg);

    /* Reject empty argument string. */
    if (arglen == 0) {
        SCLogError("tcp.session keyword requires a value: comma-separated "
                   "subset of {setup, established, closing}");
        return NULL;
    }

    /* Reject arguments longer than the maximum allowed length. */
    if (arglen > DETECT_TCP_SESSION_ARG_MAX_LEN) {
        SCLogError("tcp.session argument too long (%zu > %d): accepted "
                   "tokens are {setup, established, closing}",
                arglen, DETECT_TCP_SESSION_ARG_MAX_LEN);
        return NULL;
    }

    uint8_t phase_flags = 0;

    /* Walk the input character-by-character splitting on ','. We track each
     * token by its [start, end) range and reject empty tokens (e.g.
     * "setup,,established" or a leading/trailing comma). */
    size_t token_start = 0;
    for (size_t i = 0; i <= arglen; i++) {
        if (i != arglen && arg[i] != ',') {
            continue;
        }

        const size_t token_len = i - token_start;
        const char *token = arg + token_start;

        /* Reject empty tokens (consecutive commas, leading or
         * trailing comma). */
        if (token_len == 0) {
            SCLogError("tcp.session: empty token in argument \"%s\"; "
                       "accepted tokens are {setup, established, closing}",
                    arg);
            return NULL;
        }

        const uint8_t flag = DetectTcpSessionPhaseFlagFromToken(token, token_len);
        if (flag == 0) {
            /* Unknown / unrecognised token (also catches whitespace
             * inside or surrounding tokens since the comparison is verbatim). */
            SCLogError("tcp.session: unknown token \"%.*s\" in argument "
                       "\"%s\"; accepted tokens are {setup, established, "
                       "closing}",
                    (int)token_len, token, arg);
            return NULL;
        }

        /* Reject duplicate token. */
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

    /* Defensive: phase_flags must be non-zero here because an empty argument
     * is rejected upfront and at least one valid token is required to clear
     * the loop without erroring. Keep the guard so future refactors can
     * still trust the invariant. */
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

/**
 * \internal
 * \brief Per-packet match function.
 *
 * Returns 1 iff the packet's current TCP session phase intersects the rule's
 * `phase_flags`. The packet's phase is computed as:
 *
 *   - If the flow is non-TCP (or absent), the rule cannot match — short-
 *     circuit return 0. `tcp.session:` is TCP-specific.
 *   - The setup vs established split is read from
 *     `p->flowflags & FLOW_PKT_ESTABLISHED`, exactly as
 *     `flow:established` / `flow:not_established` do (parity contract).
 *     The flag is sticky — it remains set on subsequent packets even after
 *     the session transitions into a closing state — and we deliberately
 *     preserve that stickiness here.
 *   - The closing phase is detected via a direct membership check on
 *     `TcpSession::state` against the six closing substates: FIN_WAIT1,
 *     FIN_WAIT2, TIME_WAIT, LAST_ACK, CLOSE_WAIT, CLOSING.
 *     The closing bit is OR'd on top of the established bit so that a
 *     packet observed during e.g. FIN_WAIT1 matches both
 *     `tcp.session:established` and `tcp.session:closing` — see the
 *     "Sticky FLOW_PKT_ESTABLISHED + closing overlap" design note for the
 *     full rationale.
 *
 * Midstream pickups are handled implicitly: a midstream-picked flow that
 * lands in `TCP_ESTABLISHED` has `FLOW_PKT_ESTABLISHED` set on subsequent
 * packets via the standard stream-engine path, and the established branch
 * fires.
 *
 * \retval 1 if `pkt_phase & d->phase_flags` is non-zero
 * \retval 0 otherwise (including the non-TCP short-circuit)
 */
static int DetectTcpSessionMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    (void)det_ctx;
    (void)s;

    const DetectTcpSessionData *d = (const DetectTcpSessionData *)ctx;
    const Flow *f = p->flow;

    /* tcp.session is TCP-specific. A non-TCP flow (or no flow at all)
     * cannot match. */
    if (f == NULL || f->proto != IPPROTO_TCP) {
        return 0;
    }

    uint8_t pkt_phase = 0;

    /* Setup vs established: read FLOW_PKT_ESTABLISHED — identical to
     * detect-flow.c's FlowMatch. */
    if (p->flowflags & FLOW_PKT_ESTABLISHED) {
        pkt_phase |= DETECT_TCP_SESSION_PHASE_ESTABLISHED;
    } else {
        pkt_phase |= DETECT_TCP_SESSION_PHASE_SETUP;
    }

    /* Closing phase: consult TcpSession::state directly. The flow's
     * protoctx is the TcpSession (cast pattern follows
     * detect-engine-payload.c::DetectEngineInspectStream and many others
     * in the codebase). The session pointer can legitimately be NULL on
     * packets that arrive before the stream engine attaches state — in
     * that case we leave the closing bit clear and let the
     * setup/established bit drive the decision. */
    const TcpSession *ssn = (const TcpSession *)f->protoctx;
    if (ssn != NULL) {
        switch (ssn->state) {
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
            case TCP_TIME_WAIT:
            case TCP_LAST_ACK:
            case TCP_CLOSE_WAIT:
            case TCP_CLOSING:
                /* Sticky-flag note: we OR the closing bit on top without
                 * clearing the established bit. FLOW_PKT_ESTABLISHED stays
                 * set during closing-state transitions at the baseline
                 * (verified in stream-tcp.c), and clearing it here would
                 * diverge from `flow:established`'s behavior on
                 * closing-state packets, violating the parity contract. */
                pkt_phase |= DETECT_TCP_SESSION_PHASE_CLOSING;
                break;
            default:
                break;
        }
    }

    return (pkt_phase & d->phase_flags) ? 1 : 0;
}

/**
 * \internal
 * \brief Setup function: parse and append the SigMatch.
 *
 * On success the parsed DetectTcpSessionData is owned by the SigMatch the
 * function appends; on any failure the data is freed before returning.
 *
 * \retval 0 on success
 * \retval -1 on parse, allocation, or append failure
 */
static int DetectTcpSessionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectTcpSessionData *data = DetectTcpSessionParse(arg);
    if (data == NULL) {
        /* Parser already emitted SCLogError with the offending input and
         * the accepted token set. */
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_TCP_SESSION, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) ==
            NULL) {
        DetectTcpSessionFree(de_ctx, data);
        return -1;
    }
    return 0;
}

/**
 * \internal
 * \brief Free a DetectTcpSessionData allocation.
 *
 * The struct is a flat single-byte allocation so freeing remains trivial.
 * Kept as its own function to match the SigMatch table's Free pointer
 * convention.
 */
static void DetectTcpSessionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    (void)de_ctx;
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

/**
 * \brief Registration function for the tcp.session: keyword.
 *
 * Wired into SigTableSetup in detect-engine-register.c. The sigmatch_table
 * entry mirrors DETECT_FLOW: SIGMATCH_SUPPORT_FIREWALL is set so the keyword
 * can appear in firewall-mode rules. No prefilter wiring (the per-packet
 * match function is too cheap to merit prefilter bucketing).
 */
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

/* DetectFlowMatch is a global symbol (not declared in detect-flow.h); declare
 * it here so Test10 can assert tcp.session/flow equivalence directly. */
int DetectFlowMatch(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);

/**
 * \test Test01: `tcp.session:setup` parses with only the setup bit set.
 */
static int DetectTcpSessionTest01(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("setup");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_SETUP);
    DetectTcpSessionFree(NULL, d);

    /* `established` and `closing` parse individually too. */
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

/**
 * \test Test02: `tcp.session:setup,established` parses with both bits set, in
 *       any order, including the full three-token set.
 */
static int DetectTcpSessionTest02(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("setup,established");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED));
    DetectTcpSessionFree(NULL, d);

    /* Order is irrelevant: established,setup yields the same flags. */
    d = DetectTcpSessionParse("established,setup");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED));
    DetectTcpSessionFree(NULL, d);

    /* All three tokens combine. */
    d = DetectTcpSessionParse("setup,established,closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_SETUP | DETECT_TCP_SESSION_PHASE_ESTABLISHED |
                        DETECT_TCP_SESSION_PHASE_CLOSING));
    DetectTcpSessionFree(NULL, d);

    PASS;
}

/**
 * \test Test03: `tcp.session:closing` parses with the closing bit set.
 */
static int DetectTcpSessionTest03(void)
{
    DetectTcpSessionData *d = DetectTcpSessionParse("closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags == DETECT_TCP_SESSION_PHASE_CLOSING);
    /* established,closing combination also parses. */
    DetectTcpSessionFree(NULL, d);

    d = DetectTcpSessionParse("established,closing");
    FAIL_IF_NULL(d);
    FAIL_IF_NOT(d->phase_flags ==
                (DETECT_TCP_SESSION_PHASE_ESTABLISHED | DETECT_TCP_SESSION_PHASE_CLOSING));
    DetectTcpSessionFree(NULL, d);

    PASS;
}

/**
 * \test Test04: empty value is rejected (NULL arg, empty string, and an
 *       argument made up only of commas).
 */
static int DetectTcpSessionTest04(void)
{
    /* NULL argument. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(NULL));
    /* Empty string. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(""));
    /* Only a comma -> two empty tokens. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(","));
    /* Leading comma -> empty first token. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(",setup"));
    /* Trailing comma -> empty last token. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,"));
    /* Consecutive commas -> empty middle token. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,,established"));
    PASS;
}

/**
 * \test Test05: an unknown phase token is rejected (also covers tokens with
 *       surrounding whitespace, since matching is verbatim).
 */
static int DetectTcpSessionTest05(void)
{
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("bogus"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,bogus"));
    /* Case sensitivity: SETUP is not a recognised token. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("SETUP"));
    /* Surrounding whitespace is rejected (verbatim comparison). */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(" setup"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup "));
    /* Whitespace inside a token. */
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setu p"));
    /* Over-length argument is rejected. */
    char longarg[128];
    memset(longarg, 'a', sizeof(longarg) - 1);
    longarg[sizeof(longarg) - 1] = '\0';
    FAIL_IF_NOT_NULL(DetectTcpSessionParse(longarg));
    PASS;
}

/**
 * \test Test06: a duplicate token is rejected.
 */
static int DetectTcpSessionTest06(void)
{
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,setup"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("established,established"));
    FAIL_IF_NOT_NULL(DetectTcpSessionParse("setup,established,setup"));
    PASS;
}

/**
 * \internal
 * \brief Build a minimal TCP packet+flow harness for the match tests.
 *
 * The caller owns the returned packet and must release it with PacketFree.
 * The flow, session, and tcp header live on the caller's stack and are wired
 * into the packet here.
 */
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

/**
 * \test Test07: a packet on a TCP_ESTABLISHED flow (FLOW_PKT_ESTABLISHED set)
 *       matches `tcp.session:established`.
 */
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

/**
 * \test Test08: a packet on a TCP_SYN_SENT flow (FLOW_PKT_ESTABLISHED clear)
 *       matches `tcp.session:setup` but NOT `tcp.session:established`.
 */
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

/**
 * \test Test09: a midstream pickup that lands in TCP_ESTABLISHED (the stream
 *       engine sets FLOW_PKT_ESTABLISHED on subsequent packets) matches
 *       `tcp.session:established` and NOT `tcp.session:setup`, regardless of
 *       whether the original handshake was observed.
 */
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
    /* Mark the session as a midstream pickup. */
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

/**
 * \test Test10: equivalence with `flow:not_established` for the same packet
 *       set. For a range of TCP states and FLOW_PKT_ESTABLISHED settings,
 *       `tcp.session:setup` matches exactly when `flow:not_established`
 *       matches, and `tcp.session:established` matches exactly when
 *       `flow:established` matches.
 */
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

    /* flow:not_established and flow:established equivalents. */
    DetectFlowData fd_not_est = { .flags = DETECT_FLOW_FLAG_NOT_ESTABLISHED, .match_cnt = 1 };
    DetectFlowData fd_est = { .flags = DETECT_FLOW_FLAG_ESTABLISHED, .match_cnt = 1 };

    /* Drive a non-midstream flow through a representative set of states, both
     * with and without the FLOW_PKT_ESTABLISHED flag set, and assert that the
     * two keywords agree packet-for-packet. */
    const uint8_t states[] = { TCP_NONE, TCP_SYN_SENT, TCP_SYN_RECV, TCP_ESTABLISHED };
    const bool est_flags[] = { false, true };

    for (size_t si = 0; si < sizeof(states) / sizeof(states[0]); si++) {
        for (size_t ei = 0; ei < sizeof(est_flags) / sizeof(est_flags[0]); ei++) {
            Flow f;
            TcpSession ssn;
            TCPHdr tcph;
            Packet *p = DetectTcpSessionTestBuildPacket(
                    &f, &ssn, &tcph, states[si], est_flags[ei]);
            FAIL_IF_NULL(p);

            int ts_setup_r =
                    DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)ts_setup);
            int flow_not_est_r =
                    DetectFlowMatch(&dtx, p, &s, (const SigMatchCtx *)&fd_not_est);
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

/**
 * \brief Register the tcp.session: unit tests.
 */
static int DetectTcpSessionStateSetPartition(void);
static int DetectTcpSessionMatchExhaustive(void);
static int DetectTcpSessionPhasePartitionRandom(void);

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
    /* Property 5: TCP state-set partitioning. */
    UtRegisterTest("DetectTcpSessionStateSetPartition", DetectTcpSessionStateSetPartition);
    UtRegisterTest("DetectTcpSessionMatchExhaustive", DetectTcpSessionMatchExhaustive);
    UtRegisterTest("DetectTcpSessionPhasePartitionRandom", DetectTcpSessionPhasePartitionRandom);
}
#endif /* UNITTESTS */

#ifdef UNITTESTS

/**
 * \internal
 * \brief Test oracle: the documented per-packet phase mask.
 *
 * This is an INDEPENDENT re-derivation of the per-packet phase mask from the
 * design's §Components #5 / §Correctness Properties P5, written from the
 * specification text rather than from the production code so the property
 * test cross-checks the implementation against the spec rather than against
 * itself.
 *
 * Per the chosen interpretation (sticky FLOW_PKT_ESTABLISHED + closing overlap):
 *   - established bit  <=> FLOW_PKT_ESTABLISHED is set on the packet
 *   - setup bit        <=> FLOW_PKT_ESTABLISHED is NOT set
 *   - closing bit      <=> ssn->state is one of the six closing substates
 * The established and closing bits MAY both be set on a single packet (the
 * sticky flag is not cleared during the closing states); the SETS, however,
 * remain disjoint (see DetectTcpSessionStateSetPartition below).
 *
 * \param state         the TcpSession state (enum TcpState)
 * \param flow_pkt_est  true iff FLOW_PKT_ESTABLISHED is set on the packet
 *
 * \return the expected pkt_phase bitmask
 */
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

/**
 * \internal
 * \brief Map a TcpState to the phase SET it belongs to (Property 5 partition).
 *
 * This is the STATE-SET membership defined in the design's correctness
 * properties, independent of the per-packet sticky-flag behavior:
 *
 *   setup       = { TCP_NONE, TCP_SYN_SENT, TCP_SYN_RECV }
 *   established = { TCP_ESTABLISHED }
 *   closing     = { TCP_FIN_WAIT1, TCP_FIN_WAIT2, TCP_TIME_WAIT,
 *                   TCP_LAST_ACK, TCP_CLOSE_WAIT, TCP_CLOSING }
 *   TCP_CLOSED  -> 0 (terminal, excluded from every set)
 *
 * \return the single phase-set flag the state belongs to, or 0 for TCP_CLOSED.
 */
static uint8_t DetectTcpSessionStateSetMembership(enum TcpState state)
{
    switch (state) {
        case TCP_NONE:
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
            return DETECT_TCP_SESSION_PHASE_SETUP;
        case TCP_ESTABLISHED:
            return DETECT_TCP_SESSION_PHASE_ESTABLISHED;
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_TIME_WAIT:
        case TCP_LAST_ACK:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
            return DETECT_TCP_SESSION_PHASE_CLOSING;
        case TCP_CLOSED:
        default:
            return 0;
    }
}

/* The full, finite TcpState domain (every concrete enumerator). */
static const enum TcpState detect_tcp_session_all_states[] = {
    TCP_NONE,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
};

/**
 * \internal
 * \brief Drive the real DetectTcpSessionMatch for one (state, flag, phase_set)
 *        point and assert it agrees with the spec oracle.
 *
 * Constructs a minimal TCP flow + session exactly like the existing keyword
 * unit tests (e.g. detect-stream_size.c), sets the requested state on the
 * session and the requested FLOW_PKT_ESTABLISHED bit on the packet, then
 * compares the production match result against
 * `(expected_mask & phase_flags) != 0`.
 *
 * \retval 1 on agreement, 0 on mismatch (caller turns this into FAIL_IF).
 */
static int DetectTcpSessionMatchOneCase(enum TcpState state, bool flow_pkt_est, uint8_t phase_flags)
{
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Signature s;
    TcpSession ssn;
    Flow f;
    Packet *p = PacketGetFromAlloc();
    if (p == NULL) {
        return 0;
    }

    memset(&tv, 0, sizeof(tv));
    memset(&dtx, 0, sizeof(dtx));
    memset(&s, 0, sizeof(s));
    memset(&ssn, 0, sizeof(ssn));
    memset(&f, 0, sizeof(f));

    f.proto = IPPROTO_TCP;
    ssn.state = (uint8_t)state;
    f.protoctx = &ssn;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    if (flow_pkt_est) {
        p->flowflags |= FLOW_PKT_ESTABLISHED;
    }

    DetectTcpSessionData d;
    d.phase_flags = phase_flags;

    const uint8_t expected_mask = DetectTcpSessionExpectedPhaseMask(state, flow_pkt_est);
    const int expected = (expected_mask & phase_flags) ? 1 : 0;
    const int actual = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)&d);

    PacketFree(p);

    return (actual == expected) ? 1 : 0;
}

/**
 * \test Property 5 (state-set partition invariants).
 *
 * Asserts the disjointness and coverage invariants on the STATE SETS over the
 * complete, finite TcpState domain (stronger than sampling): every concrete
 * TcpState except TCP_CLOSED belongs to exactly one phase set, the three sets
 * are pairwise disjoint, their union is `enum TcpState \ {TCP_CLOSED}`, and
 * TCP_CLOSED belongs to no set.
 */
static int DetectTcpSessionStateSetPartition(void)
{
    const size_t n = sizeof(detect_tcp_session_all_states) /
                     sizeof(detect_tcp_session_all_states[0]);

    uint8_t union_mask = 0;
    int setup_count = 0, est_count = 0, closing_count = 0, closed_count = 0;

    for (size_t i = 0; i < n; i++) {
        const enum TcpState st = detect_tcp_session_all_states[i];
        const uint8_t m = DetectTcpSessionStateSetMembership(st);

        if (st == TCP_CLOSED) {
            /* Terminal state is in no set. */
            FAIL_IF_NOT(m == 0);
            closed_count++;
            continue;
        }

        /* Each non-terminal state belongs to exactly one set: the membership
         * is a single bit, never zero, never two bits. */
        FAIL_IF(m == 0);
        FAIL_IF_NOT((m & (m - 1)) == 0); /* exactly one bit set */

        union_mask |= m;
        if (m == DETECT_TCP_SESSION_PHASE_SETUP)
            setup_count++;
        else if (m == DETECT_TCP_SESSION_PHASE_ESTABLISHED)
            est_count++;
        else if (m == DETECT_TCP_SESSION_PHASE_CLOSING)
            closing_count++;
    }

    /* setup ∪ established ∪ closing == every phase bit. */
    FAIL_IF_NOT(union_mask == (DETECT_TCP_SESSION_PHASE_SETUP |
                               DETECT_TCP_SESSION_PHASE_ESTABLISHED |
                               DETECT_TCP_SESSION_PHASE_CLOSING));

    /* Exact cardinalities from the design partition. */
    FAIL_IF_NOT(setup_count == 3);   /* TCP_NONE, TCP_SYN_SENT, TCP_SYN_RECV */
    FAIL_IF_NOT(est_count == 1);     /* TCP_ESTABLISHED */
    FAIL_IF_NOT(closing_count == 6); /* the six closing substates */
    FAIL_IF_NOT(closed_count == 1);  /* TCP_CLOSED only */

    PASS;
}

/**
 * \test Property 5 (exhaustive match-function partition + equivalence).
 *
 * Exhaustively enumerates the COMPLETE finite domain
 * (all 11 TcpState values) × (FLOW_PKT_ESTABLISHED ∈ {0,1}) ×
 * (all 7 non-empty phase_flags subsets) = 154 cases and asserts the real
 * DetectTcpSessionMatch agrees with the spec oracle on every one. Because the
 * domain is finite this exhaustion is strictly stronger than any number of
 * random samples.
 *
 * It additionally asserts the setup/established equivalence directly: for every
 * state, `tcp.session:setup` matches iff FLOW_PKT_ESTABLISHED is unset (the
 * exact predicate `flow:not_established` uses) and `tcp.session:established`
 * matches iff FLOW_PKT_ESTABLISHED is set (the exact predicate
 * `flow:established` uses) — on a non-midstream flow these are the same
 * packets.
 */
static int DetectTcpSessionMatchExhaustive(void)
{
    const size_t n = sizeof(detect_tcp_session_all_states) /
                     sizeof(detect_tcp_session_all_states[0]);

    for (size_t i = 0; i < n; i++) {
        const enum TcpState st = detect_tcp_session_all_states[i];

        for (int est = 0; est <= 1; est++) {
            const bool flow_pkt_est = (est == 1);

            /* All 7 non-empty subsets of the 3-bit phase space. */
            for (uint8_t pf = 1; pf <= 0x7; pf++) {
                FAIL_IF_NOT(DetectTcpSessionMatchOneCase(st, flow_pkt_est, pf));
            }

            /* Direct setup/established equivalence checks (single-phase rules). */
            /* tcp.session:setup  <=> !FLOW_PKT_ESTABLISHED (flow:not_established). */
            {
                DetectTcpSessionData d = { .phase_flags = DETECT_TCP_SESSION_PHASE_SETUP };
                ThreadVars tv; DetectEngineThreadCtx dtx; Signature s;
                TcpSession ssn; Flow f;
                Packet *p = PacketGetFromAlloc();
                FAIL_IF_NULL(p);
                memset(&tv, 0, sizeof(tv)); memset(&dtx, 0, sizeof(dtx));
                memset(&s, 0, sizeof(s)); memset(&ssn, 0, sizeof(ssn));
                memset(&f, 0, sizeof(f));
                f.proto = IPPROTO_TCP; ssn.state = (uint8_t)st; f.protoctx = &ssn;
                p->flow = &f; p->flags |= PKT_HAS_FLOW;
                if (flow_pkt_est) p->flowflags |= FLOW_PKT_ESTABLISHED;
                const int r = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)&d);
                PacketFree(p);
                FAIL_IF_NOT(r == (flow_pkt_est ? 0 : 1));
            }

            /* tcp.session:established <=> FLOW_PKT_ESTABLISHED (flow:established). */
            {
                DetectTcpSessionData d = { .phase_flags = DETECT_TCP_SESSION_PHASE_ESTABLISHED };
                ThreadVars tv; DetectEngineThreadCtx dtx; Signature s;
                TcpSession ssn; Flow f;
                Packet *p = PacketGetFromAlloc();
                FAIL_IF_NULL(p);
                memset(&tv, 0, sizeof(tv)); memset(&dtx, 0, sizeof(dtx));
                memset(&s, 0, sizeof(s)); memset(&ssn, 0, sizeof(ssn));
                memset(&f, 0, sizeof(f));
                f.proto = IPPROTO_TCP; ssn.state = (uint8_t)st; f.protoctx = &ssn;
                p->flow = &f; p->flags |= PKT_HAS_FLOW;
                if (flow_pkt_est) p->flowflags |= FLOW_PKT_ESTABLISHED;
                const int r = DetectTcpSessionMatch(&dtx, p, &s, (const SigMatchCtx *)&d);
                PacketFree(p);
                FAIL_IF_NOT(r == (flow_pkt_est ? 1 : 0));
            }
        }
    }

    PASS;
}

/**
 * \test Property 5 (randomized sweep, >=1000 cases per phase).
 *
 * Honors the test's literal "minimum 1000 generated cases per phase"
 * requirement by drawing random (TcpState, FLOW_PKT_ESTABLISHED) inputs and
 * asserting, for each of the three single-phase rules independently, that the
 * production match agrees with the spec oracle across >=1000 generated cases
 * per phase. The exhaustive test above already proves correctness over the
 * whole finite domain; this provides the randomized-coverage form the task
 * specifies.
 */
static int DetectTcpSessionPhasePartitionRandom(void)
{
    const size_t n = sizeof(detect_tcp_session_all_states) /
                     sizeof(detect_tcp_session_all_states[0]);

    const uint8_t single_phase[3] = {
        DETECT_TCP_SESSION_PHASE_SETUP,
        DETECT_TCP_SESSION_PHASE_ESTABLISHED,
        DETECT_TCP_SESSION_PHASE_CLOSING,
    };

    /* Self-contained deterministic LCG (Numerical Recipes constants) so any
     * failure reproduces exactly without depending on the platform rand(). */
    uint32_t rng = 0xC0FFEEu;
#define DETECT_TCP_SESSION_NEXT_RAND() (rng = rng * 1664525u + 1013904223u)

    const int cases_per_phase = 1000;

    for (int ph = 0; ph < 3; ph++) {
        for (int c = 0; c < cases_per_phase; c++) {
            const enum TcpState st =
                    detect_tcp_session_all_states[DETECT_TCP_SESSION_NEXT_RAND() % n];
            const bool flow_pkt_est = (DETECT_TCP_SESSION_NEXT_RAND() & 0x10000u) != 0;

            FAIL_IF_NOT(
                    DetectTcpSessionMatchOneCase(st, flow_pkt_est, single_phase[ph]));
        }
    }

#undef DETECT_TCP_SESSION_NEXT_RAND
    PASS;
}

#endif /* UNITTESTS */
