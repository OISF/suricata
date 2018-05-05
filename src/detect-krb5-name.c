/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-krb5-name.h"

#ifdef HAVE_RUST

#include "app-layer-krb5.h"
#include "rust-krb-detect-gen.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([!]?)\\s*([A-z0-9\\.]+|\"[A-z0-9_\\.]+\")\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectKrb5CNameMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);
static int DetectKrb5CNameSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectKrb5CNameRegisterTests (void);

static int DetectKrb5SNameMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);
static int DetectKrb5SNameSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectKrb5SNameRegisterTests (void);

static void DetectKrb5NameFree (void *);

static int DetectEngineInspectKRB5Generic(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int g_krb5_name_list_id = 0;

/**
 * \brief Registration function for krb5.cname and krb5.sname: keywords
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectKrb5NameRegister(void) {
    sigmatch_table[DETECT_AL_KRB5_CNAME].name = "krb5.cname";
    sigmatch_table[DETECT_AL_KRB5_CNAME].desc = "match Kerberos 5 ticket client name";
    sigmatch_table[DETECT_AL_KRB5_CNAME].url = DOC_URL DOC_VERSION "/rules/kerberos-keywords.html#krb5-cname";
    sigmatch_table[DETECT_AL_KRB5_CNAME].Match = NULL;
    sigmatch_table[DETECT_AL_KRB5_CNAME].AppLayerTxMatch = DetectKrb5CNameMatch;
    sigmatch_table[DETECT_AL_KRB5_CNAME].Setup = DetectKrb5CNameSetup;
    sigmatch_table[DETECT_AL_KRB5_CNAME].Free = DetectKrb5NameFree;
    sigmatch_table[DETECT_AL_KRB5_CNAME].RegisterTests = DetectKrb5CNameRegisterTests;

    sigmatch_table[DETECT_AL_KRB5_SNAME].name = "krb5.sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].desc = "match Kerberos 5 ticket server name";
    sigmatch_table[DETECT_AL_KRB5_SNAME].url = DOC_URL DOC_VERSION "/rules/kerberos-keywords.html#krb5-sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].Match = NULL;
    sigmatch_table[DETECT_AL_KRB5_SNAME].AppLayerTxMatch = DetectKrb5SNameMatch;
    sigmatch_table[DETECT_AL_KRB5_SNAME].Setup = DetectKrb5SNameSetup;
    sigmatch_table[DETECT_AL_KRB5_SNAME].Free = DetectKrb5NameFree;
    sigmatch_table[DETECT_AL_KRB5_SNAME].RegisterTests = DetectKrb5SNameRegisterTests;

    DetectAppLayerInspectEngineRegister("krb5_name",
            ALPROTO_KRB5, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectKRB5Generic);

    DetectAppLayerInspectEngineRegister("krb5_name",
            ALPROTO_KRB5, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectKRB5Generic);

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    g_krb5_name_list_id = DetectBufferTypeRegister("krb5_name");
    SCLogDebug("g_krb5_name_list_id %d", g_krb5_name_list_id);
}

static int DetectEngineInspectKRB5Generic(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

/**
 * \brief This function is used to match KRB5 rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectKrb5Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectKrb5CNameMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    const DetectKrb5NameData *dd = (const DetectKrb5NameData *)ctx;
    uint8_t res = 0;

    SCEnter();

    if (rs_krb5_tx_cmp_cname(txv, dd->name) == 0) {
        res = 1;
    }

    if (dd->negated) {
        if (res) {
            res = 0;
        } else {
            res = 1;
        }
    }

    SCReturnInt(res);
}

/**
 * \brief This function is used to match KRB5 rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectKrb5Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectKrb5SNameMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    const DetectKrb5NameData *dd = (const DetectKrb5NameData *)ctx;
    uint8_t res = 0;

    SCEnter();

    if (rs_krb5_tx_cmp_sname(txv, dd->name) == 0) {
        res = 1;
    }

    if (dd->negated) {
        if (res) {
            res = 0;
        } else {
            res = 1;
        }
    }

    SCReturnInt(res);
}

/**
 * \brief This function is used to parse options passed via krb5.msgtype: keyword
 *
 * \param krb5str Pointer to the user provided krb5.sname options
 *
 * \retval krb5d pointer to DetectKrb5Data on success
 * \retval NULL on failure
 */
static DetectKrb5NameData *DetectKrb5NameParse (const char *krb5str)
{
    DetectKrb5NameData *krb5d = NULL;
    char negate_str[32];
    const char * result = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    krb5str, strlen(krb5str),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring(krb5str, ov, MAX_SUBSTRINGS, 1,
            negate_str, sizeof(negate_str));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    res = pcre_get_substring(krb5str, ov, MAX_SUBSTRINGS - 1, 2, &result);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    krb5d = SCMalloc(sizeof (DetectKrb5NameData));
    if (unlikely(krb5d == NULL))
        goto error;
    krb5d->name = SCStrdup((char*)result);
    if (unlikely(krb5d->name == NULL)) {
        goto error;
    }

    if (negate_str[0] == '!') {
        krb5d->negated = 1;
    } else {
        krb5d->negated = 0;
    }

    return krb5d;

error:
    if (krb5d)
        SCFree(krb5d);
    return NULL;
}

/**
 * \brief parse the options from the 'krb5.cname' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param krb5str pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectKrb5CNameSetup (DetectEngineCtx *de_ctx, Signature *s, const char *krb5str)
{
    DetectKrb5NameData *krb5d = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    krb5d = DetectKrb5NameParse(krb5str);
    if (krb5d == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_KRB5_CNAME;
    sm->ctx = (void *)krb5d;

    s->flags |= SIG_FLAG_STATE_MATCH;
    SigMatchAppendSMToList(s, sm, g_krb5_name_list_id);

    return 0;

error:
    if (krb5d != NULL)
        DetectKrb5NameFree(krb5d);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief parse the options from the 'krb5.sname' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param krb5str pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectKrb5SNameSetup (DetectEngineCtx *de_ctx, Signature *s, const char *krb5str)
{
    DetectKrb5NameData *krb5d = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    krb5d = DetectKrb5NameParse(krb5str);
    if (krb5d == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_KRB5_SNAME;
    sm->ctx = (void *)krb5d;

    s->flags |= SIG_FLAG_STATE_MATCH;
    SigMatchAppendSMToList(s, sm, g_krb5_name_list_id);

    return 0;

error:
    if (krb5d != NULL)
        DetectKrb5NameFree(krb5d);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectKrb5Data
 *
 * \param ptr pointer to DetectKrb5Data
 */
static void DetectKrb5NameFree(void *ptr) {
    DetectKrb5NameData *krb5d = (DetectKrb5NameData *)ptr;

    SCFree(krb5d->name);

    SCFree(krb5d);
}

#ifdef UNITTESTS

static int DetectKrb5SNameParseTest01 (void)
{
    DetectKrb5NameData *krb5d = DetectKrb5NameParse("krbtgt");
    FAIL_IF_NULL(krb5d);
    FAIL_IF(strcmp(krb5d->name,"krbtgt") != 0);
    DetectKrb5NameFree(krb5d);
    PASS;
}

static int DetectKrb5CNameSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert krb5 any any -> any any (krb5.cname:krbtgt; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectKrb5SNameSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert krb5 any any -> any any (krb5.sname:krbtgt; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectKrb5CName
 */
static void DetectKrb5CNameRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectKrb5CNameParseTest01", DetectKrb5SNameParseTest01);
    UtRegisterTest("DetectKrb5CNameSignatureTest01",
                   DetectKrb5CNameSignatureTest01);
#endif /* UNITTESTS */
}

/**
 * \brief this function registers unit tests for DetectKrb5SName
 */
static void DetectKrb5SNameRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectKrb5SNameParseTest01", DetectKrb5SNameParseTest01);
    UtRegisterTest("DetectKrb5SNameSignatureTest01",
                   DetectKrb5SNameSignatureTest01);
#endif /* UNITTESTS */
}

#else /* HAVE_RUST */

void DetectKrb5NameRegister(void)
{
}

#endif /* HAVE_RUST */
