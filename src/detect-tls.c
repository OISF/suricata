/*
 * Copyright (C) 2011-2012 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 * Implements the tls.* keywords
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "app-layer-ssl.h"
#include "detect-tls.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */

#define PARSE_REGEX  "^([A-z0-9\\s\\-\\.=,\\*@]+|\"[A-z0-9\\s\\-\\.=,\\*@]+\")\\s*$"
#define PARSE_REGEX_FINGERPRINT  "^([A-z0-9\\:\\*]+|\"[A-z0-9\\:\\* ]+\")\\s*$"

static DetectParseRegex subject_parse_regex;
static DetectParseRegex issuerdn_parse_regex;
static DetectParseRegex fingerprint_parse_regex;

static int DetectTlsSubjectMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectTlsSubjectSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTlsSubjectFree(DetectEngineCtx *, void *);

static int DetectTlsIssuerDNMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectTlsIssuerDNSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTlsIssuerDNFree(DetectEngineCtx *, void *);

static int DetectTlsFingerprintMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectTlsFingerprintSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTlsFingerprintFree(DetectEngineCtx *, void *);

static int DetectTlsStoreSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectTlsStorePostMatch (DetectEngineThreadCtx *det_ctx,
        Packet *, const Signature *s, const SigMatchCtx *unused);

static int g_tls_cert_list_id = 0;

static uint8_t InspectTlsCert(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \brief Registration function for keyword: tls.version
 */
void DetectTlsRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_SUBJECT].name = "tls.subject";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].desc = "match TLS/SSL certificate Subject field";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].url = "/rules/tls-keywords.html#tls-subject";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].AppLayerTxMatch = DetectTlsSubjectMatch;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].Setup = DetectTlsSubjectSetup;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].Free  = DetectTlsSubjectFree;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].flags = SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].alternative = DETECT_AL_TLS_CERT_SUBJECT;

    sigmatch_table[DETECT_AL_TLS_ISSUERDN].name = "tls.issuerdn";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].desc = "match TLS/SSL certificate IssuerDN field";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].url = "/rules/tls-keywords.html#tls-issuerdn";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].AppLayerTxMatch = DetectTlsIssuerDNMatch;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].Setup = DetectTlsIssuerDNSetup;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].Free  = DetectTlsIssuerDNFree;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].flags = SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].alternative = DETECT_AL_TLS_CERT_ISSUER;

    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].name = "tls.fingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].desc = "match TLS/SSL certificate SHA1 fingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].url = "/rules/tls-keywords.html#tls-fingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].AppLayerTxMatch = DetectTlsFingerprintMatch;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].Setup = DetectTlsFingerprintSetup;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].Free  = DetectTlsFingerprintFree;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].flags = SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].alternative = DETECT_AL_TLS_CERT_FINGERPRINT;

    sigmatch_table[DETECT_AL_TLS_STORE].name = "tls_store";
    sigmatch_table[DETECT_AL_TLS_STORE].alias = "tls.store";
    sigmatch_table[DETECT_AL_TLS_STORE].desc = "store TLS/SSL certificate on disk";
    sigmatch_table[DETECT_AL_TLS_STORE].url = "/rules/tls-keywords.html#tls-store";
    sigmatch_table[DETECT_AL_TLS_STORE].Match = DetectTlsStorePostMatch;
    sigmatch_table[DETECT_AL_TLS_STORE].Setup = DetectTlsStoreSetup;
    sigmatch_table[DETECT_AL_TLS_STORE].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX, &subject_parse_regex);
    DetectSetupParseRegexes(PARSE_REGEX, &issuerdn_parse_regex);
    DetectSetupParseRegexes(PARSE_REGEX_FINGERPRINT, &fingerprint_parse_regex);

    g_tls_cert_list_id = DetectBufferTypeRegister("tls_cert");

    DetectAppLayerInspectEngineRegister2(
            "tls_cert", ALPROTO_TLS, SIG_FLAG_TOCLIENT, TLS_STATE_CERT_READY, InspectTlsCert, NULL);
}

/**
 * \brief match the specified Subject on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsSubjectMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    const DetectTlsData *tls_data = (const DetectTlsData *)m;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_subject != NULL) {
        SCLogDebug("TLS: Subject is [%s], looking for [%s]\n",
                   connp->cert0_subject, tls_data->subject);

        if (strstr(connp->cert0_subject, tls_data->subject) != NULL) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;
            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsSubjectParse (DetectEngineCtx *de_ctx, const char *str, bool negate)
{
    DetectTlsData *tls = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr;
    char *orig = NULL;
    char *tmp_str;
    uint32_t flag = 0;

    ret = DetectParsePcreExec(&subject_parse_regex, str, 0, 0);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.subject option");
        goto error;
    }

    if (negate)
        flag = DETECT_CONTENT_NEGATED;

    res = pcre2_substring_get_bynumber(
            subject_parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->subject = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);

    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"') {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->subject = SCStrdup(tmp_str);
    if (unlikely(tls->subject == NULL)) {
        goto error;
    }

    SCFree(orig);

    SCLogDebug("will look for TLS subject %s", tls->subject);

    return tls;

error:
    if (orig != NULL)
        SCFree(orig);
    if (tls != NULL)
        DetectTlsSubjectFree(de_ctx, tls);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsSubjectSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    tls = DetectTlsSubjectParse(de_ctx, str, s->init_data->negated);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_TLS_SUBJECT;
    sm->ctx = (void *)tls;

    SigMatchAppendSMToList(s, sm, g_tls_cert_list_id);
    return 0;

error:
    if (tls != NULL)
        DetectTlsSubjectFree(de_ctx, tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param id_d pointer to DetectTlsData
 */
static void DetectTlsSubjectFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    if (ptr == NULL)
        return;
    if (id_d->subject != NULL)
        SCFree(id_d->subject);
    SCFree(id_d);
}

/**
 * \brief match the specified IssuerDN on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsIssuerDNMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    const DetectTlsData *tls_data = (const DetectTlsData *)m;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_issuerdn != NULL) {
        SCLogDebug("TLS: IssuerDN is [%s], looking for [%s]\n",
                   connp->cert0_issuerdn, tls_data->issuerdn);

        if (strstr(connp->cert0_issuerdn, tls_data->issuerdn) != NULL) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;
            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsIssuerDNParse(DetectEngineCtx *de_ctx, const char *str, bool negate)
{
    DetectTlsData *tls = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr;
    char *orig = NULL;
    char *tmp_str;
    uint32_t flag = 0;

    ret = DetectParsePcreExec(&issuerdn_parse_regex, str, 0, 0);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.issuerdn option");
        goto error;
    }

    if (negate)
        flag = DETECT_CONTENT_NEGATED;

    res = pcre2_substring_get_bynumber(
            issuerdn_parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->issuerdn = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);

    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"')
    {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->issuerdn = SCStrdup(tmp_str);
    if (unlikely(tls->issuerdn == NULL)) {
        goto error;
    }

    SCFree(orig);

    SCLogDebug("Will look for TLS issuerdn %s", tls->issuerdn);

    return tls;

error:
    if (orig != NULL)
        SCFree(orig);
    if (tls != NULL)
        DetectTlsIssuerDNFree(de_ctx, tls);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsIssuerDNSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    tls = DetectTlsIssuerDNParse(de_ctx, str, s->init_data->negated);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_TLS_ISSUERDN;
    sm->ctx = (void *)tls;

    SigMatchAppendSMToList(s, sm, g_tls_cert_list_id);
    return 0;

error:
    if (tls != NULL)
        DetectTlsIssuerDNFree(de_ctx, tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param id_d pointer to DetectTlsData
 */
static void DetectTlsIssuerDNFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    SCFree(id_d->issuerdn);
    SCFree(id_d);
}

/**
 * \brief This function is used to parse fingerprint passed via keyword: "fingerprint"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided fingerprint option
 *
 * \retval pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsFingerprintParse (DetectEngineCtx *de_ctx, const char *str, bool negate)
{
    DetectTlsData *tls = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr;
    char *orig;
    char *tmp_str;
    uint32_t flag = 0;

    ret = DetectParsePcreExec(&fingerprint_parse_regex, str, 0, 0);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.fingerprint option");
        goto error;
    }

    if (negate)
        flag = DETECT_CONTENT_NEGATED;

    res = pcre2_substring_get_bynumber(
            fingerprint_parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->fingerprint = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);

    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"')
    {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->fingerprint = SCStrdup(tmp_str);
    if (tls->fingerprint == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate fingerprint");
    }

    SCFree(orig);

    SCLogDebug("will look for TLS fingerprint %s", tls->fingerprint);

    return tls;

error:
    if (tls != NULL)
        DetectTlsFingerprintFree(de_ctx, tls);
    return NULL;

}
/**
 * \brief match the specified fingerprint on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsFingerprintMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    const DetectTlsData *tls_data = (const DetectTlsData *)m;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_fingerprint != NULL) {
        SCLogDebug("TLS: Fingerprint is [%s], looking for [%s]\n",
                   connp->cert0_fingerprint,
                   tls_data->fingerprint);

        if (tls_data->fingerprint &&
            (strstr(connp->cert0_fingerprint,
                    tls_data->fingerprint) != NULL)) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;

            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief this function is used to add the parsed "fingerprint" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param id pointer to the user provided "fingerprint" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsFingerprintSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    tls = DetectTlsFingerprintParse(de_ctx, str, s->init_data->negated);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_TLS_FINGERPRINT;
    sm->ctx = (void *)tls;

    SigMatchAppendSMToList(s, sm, g_tls_cert_list_id);
    return 0;

error:
    if (tls != NULL)
        DetectTlsFingerprintFree(de_ctx, tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param pointer to DetectTlsData
 */
static void DetectTlsFingerprintFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    if (id_d->fingerprint)
        SCFree(id_d->fingerprint);
    SCFree(id_d);
}

/**
 * \brief this function is used to add the parsed "store" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "store" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsStoreSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    sm = SigMatchAlloc();
    if (sm == NULL)
        return -1;

    sm->type = DETECT_AL_TLS_STORE;
    s->flags |= SIG_FLAG_TLSSTORE;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
    return 0;
}

/** \warning modifies Flow::alstate */
static int DetectTlsStorePostMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *unused)
{
    SCEnter();

    if (p->flow == NULL)
        return 0;

    SSLState *ssl_state = FlowGetAppState(p->flow);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    ssl_state->server_connp.cert_log_flag |= SSL_TLS_LOG_PEM;
    SCReturnInt(1);
}
