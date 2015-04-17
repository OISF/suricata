/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *         Original Idea by Matt Jonkman
 *
 * IP Reputation Module, initial API for IPV4 and IPV6 feed
 */

#include "util-error.h"
#include "util-debug.h"
#include "util-ip.h"
#include "util-radix-tree.h"
#include "util-unittest.h"
#include "suricata-common.h"
#include "threads.h"
#include "util-print.h"
#include "host.h"
#include "conf.h"
#include "detect.h"
#include "reputation.h"

/** effective reputation version, atomic as the host
 *  time out code will use it to check if a host's
 *  reputation info is outdated. */
SC_ATOMIC_DECLARE(uint32_t, srep_eversion);
/** reputation version set to the host's reputation,
 *  this will be set to 1 before rep files are loaded,
 *  so hosts will always have a minial value of 1 */
static uint32_t srep_version = 0;

static uint32_t SRepIncrVersion(void)
{
    return ++srep_version;
}

static uint32_t SRepGetVersion(void)
{
    return srep_version;
}

void SRepResetVersion(void)
{
    srep_version = 0;
}

static uint32_t SRepGetEffectiveVersion(void)
{
    return SC_ATOMIC_GET(srep_eversion);
}

static void SRepCIDRFreeUserData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

static void SRepCIDRAddNetblock(SRepCIDRTree *cidr_ctx, char *ip, int cat, int value)
{
    SReputation *user_data = NULL;
    if ((user_data = SCMalloc(sizeof(SReputation))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Error allocating memory. Exiting");
        exit(EXIT_FAILURE);
    }
    memset(user_data, 0x00, sizeof(SReputation));

    user_data->version = SRepGetVersion();
    user_data->rep[cat] = value;

    if (strchr(ip, ':') != NULL) {
        if (cidr_ctx->srepIPV6_tree[cat] == NULL) {
            cidr_ctx->srepIPV6_tree[cat] = SCRadixCreateRadixTree(SRepCIDRFreeUserData, NULL);
            if (cidr_ctx->srepIPV6_tree[cat] == NULL) {
                SCLogDebug("Error initializing Reputation IPV6 with CIDR module for cat %d", cat);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("Reputation IPV6 with CIDR module for cat %d initialized", cat);
        }

        SCLogDebug("adding ipv6 host %s", ip);
        if (SCRadixAddKeyIPV6String(ip, cidr_ctx->srepIPV6_tree[cat], (void *)user_data) == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                        "failed to add ipv6 host %s", ip);
        }

    } else {
        if (cidr_ctx->srepIPV4_tree[cat] == NULL) {
            cidr_ctx->srepIPV4_tree[cat] = SCRadixCreateRadixTree(SRepCIDRFreeUserData, NULL);
            if (cidr_ctx->srepIPV4_tree[cat] == NULL) {
                SCLogDebug("Error initializing Reputation IPV4 with CIDR module for cat %d", cat);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("Reputation IPV4 with CIDR module for cat %d initialized", cat);
        }

        SCLogDebug("adding ipv4 host %s", ip);
        if (SCRadixAddKeyIPV4String(ip, cidr_ctx->srepIPV4_tree[cat], (void *)user_data) == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                        "failed to add ipv4 host %s", ip);
        }
    }
}

static uint8_t SRepCIDRGetIPv4IPRep(SRepCIDRTree *cidr_ctx, uint8_t *ipv4_addr, uint8_t cat)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(ipv4_addr, cidr_ctx->srepIPV4_tree[cat], &user_data);
    if (user_data == NULL)
        return 0;

    SReputation *r = (SReputation *)user_data;
    return r->rep[cat];
}

static uint8_t SRepCIDRGetIPv6IPRep(SRepCIDRTree *cidr_ctx, uint8_t *ipv6_addr, uint8_t cat)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6BestMatch(ipv6_addr, cidr_ctx->srepIPV6_tree[cat], &user_data);
    if (user_data == NULL)
        return 0;

    SReputation *r = (SReputation *)user_data;
    return r->rep[cat];
}

uint8_t SRepCIDRGetIPRepSrc(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version)
{
    uint8_t rep = 0;

    if (PKT_IS_IPV4(p))
        rep = SRepCIDRGetIPv4IPRep(cidr_ctx, (uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), cat);
    else if (PKT_IS_IPV6(p))
        rep = SRepCIDRGetIPv6IPRep(cidr_ctx, (uint8_t *)GET_IPV6_SRC_ADDR(p), cat);

    return rep;
}

uint8_t SRepCIDRGetIPRepDst(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version)
{
    uint8_t rep = 0;

    if (PKT_IS_IPV4(p))
        rep = SRepCIDRGetIPv4IPRep(cidr_ctx, (uint8_t *)GET_IPV4_DST_ADDR_PTR(p), cat);
    else if (PKT_IS_IPV6(p))
        rep = SRepCIDRGetIPv6IPRep(cidr_ctx, (uint8_t *)GET_IPV6_DST_ADDR(p), cat);

    return rep;
}

/** \brief Increment effective reputation version after
 *         a rule/reputatio reload is complete. */
void SRepReloadComplete(void)
{
    (void) SC_ATOMIC_ADD(srep_eversion, 1);
    SCLogDebug("effective Reputation version %u", SRepGetEffectiveVersion());
}

/** \brief Set effective reputation version after
 *         reputation initialization is complete. */
void SRepInitComplete(void)
{
    (void) SC_ATOMIC_SET(srep_eversion, 1);
    SCLogDebug("effective Reputation version %u", SRepGetEffectiveVersion());
}

/** \brief Check if a Host is timed out wrt ip rep, meaning a new
 *         version is in place.
 *
 *  We clean up the old version here.
 *
 *  \param h host
 *
 *  \retval 0 not timed out
 *  \retval 1 timed out
 */
int SRepHostTimedOut(Host *h)
{
    BUG_ON(h == NULL);

    if (h->iprep == NULL)
        return 1;

    uint32_t eversion = SRepGetEffectiveVersion();
    SReputation *r = h->iprep;
    if (r->version < eversion) {
        SCLogDebug("host %p has reputation version %u, "
                "effective version is %u", h, r->version, eversion);

        SCFree(h->iprep);
        h->iprep = NULL;

        HostDecrUsecnt(h);
        return 1;
    }

    return 0;
}

static int SRepCatSplitLine(char *line, uint8_t *cat, char *shortname, size_t shortname_len)
{
    size_t line_len = strlen(line);
    char *ptrs[2] = {NULL,NULL};
    int i = 0;
    int idx = 0;
    char *origline = line;

    while (i < (int)line_len) {
        if (line[i] == ',' || line[i] == '\n' || line[i] == '\0' || i == (int)(line_len - 1)) {
            line[i] = '\0';

            ptrs[idx] = line;
            idx++;

            line += (i+1);
            i = 0;

            if (line >= origline + line_len)
                break;
            if (strlen(line) == 0)
                break;
            if (idx == 2)
                break;
        } else {
            i++;
        }
    }

    if (idx != 2) {
        return -1;
    }

    SCLogDebug("%s, %s", ptrs[0], ptrs[1]);

    int c = atoi(ptrs[0]);
    if (c < 0 || c >= SREP_MAX_CATS) {
        return -1;
    }

    *cat = (uint8_t)c;
    strlcpy(shortname, ptrs[1], shortname_len);
    return 0;

}

/**
 *  \retval 0 valid
 *  \retval 1 header
 *  \retval -1 boo
 */
static int SRepSplitLine(SRepCIDRTree *cidr_ctx, char *line, Address *ip, uint8_t *cat, uint8_t *value)
{
    size_t line_len = strlen(line);
    char *ptrs[3] = {NULL,NULL,NULL};
    int i = 0;
    int idx = 0;
    char *origline = line;

    while (i < (int)line_len) {
        if (line[i] == ',' || line[i] == '\n' || line[i] == '\0' || i == (int)(line_len - 1)) {
            line[i] = '\0';

            ptrs[idx] = line;
            idx++;

            line += (i+1);
            i = 0;

            if (line >= origline + line_len)
                break;
            if (strlen(line) == 0)
                break;
            if (idx == 3)
                break;
        } else {
            i++;
        }
    }

    if (idx != 3) {
        return -1;
    }

    //SCLogInfo("%s, %s, %s", ptrs[0], ptrs[1], ptrs[2]);

    if (strcmp(ptrs[0], "ip") == 0)
        return 1;

    int c = atoi(ptrs[1]);
    if (c < 0 || c >= SREP_MAX_CATS) {
        return -1;
    }

    int v = atoi(ptrs[2]);
    if (v < 0 || v > 127) {
        return -1;
    }

    if (strchr(ptrs[0], '/') != NULL) {
        SRepCIDRAddNetblock(cidr_ctx, ptrs[0], c, v);
        return 1;
    } else {
        if (inet_pton(AF_INET, ptrs[0], &ip->address) == 1) {
            ip->family = AF_INET;
        } else if (inet_pton(AF_INET6, ptrs[0], &ip->address) == 1) {
            ip->family = AF_INET6;
        } else {
            return -1;
        }

        *cat = c;
        *value = v;
    }

    return 0;
}

#define SREP_SHORTNAME_LEN 32
static char srep_cat_table[SREP_MAX_CATS][SREP_SHORTNAME_LEN];

int SRepCatValid(uint8_t cat)
{
    if (cat >= SREP_MAX_CATS)
        return 0;

    if (strlen(srep_cat_table[cat]) == 0)
        return 0;

    return 1;
}

uint8_t SRepCatGetByShortname(char *shortname)
{
    uint8_t cat;
    for (cat = 0; cat < SREP_MAX_CATS; cat++) {
        if (strcmp(srep_cat_table[cat], shortname) == 0)
            return cat;
    }

    return 0;
}

static int SRepLoadCatFile(char *filename)
{
    int r = 0;
    FILE *fp = fopen(filename, "r");

    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening ip rep file %s: %s", filename, strerror(errno));
        return -1;
    }

    r = SRepLoadCatFileFromFD(fp);

    fclose(fp);
    fp = NULL;
    return r;
}

int SRepLoadCatFileFromFD(FILE *fp)
{
    char line[8192] = "";
    Address a;
    memset(&a, 0x00, sizeof(a));
    a.family = AF_INET;
    memset(&srep_cat_table, 0x00, sizeof(srep_cat_table));

    BUG_ON(SRepGetVersion() > 0);

    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        if (len == 0)
            continue;

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line [0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        while (isspace((unsigned char)line[--len]));

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len == 0)
            continue;

        if (line[len - 1] == '\n' || line[len - 1] == '\r') {
            line[len - 1] = '\0';
        }

        uint8_t cat = 0;
        char shortname[SREP_SHORTNAME_LEN];
        if (SRepCatSplitLine(line, &cat, shortname, sizeof(shortname)) == 0) {
            strlcpy(srep_cat_table[cat], shortname, SREP_SHORTNAME_LEN);
        } else {
            SCLogError(SC_ERR_NO_REPUTATION, "bad line \"%s\"", line);
        }
    }

    SCLogDebug("IP Rep categories:");
    int i;
    for (i = 0; i < SREP_MAX_CATS; i++) {
        if (strlen(srep_cat_table[i]) == 0)
            continue;
        SCLogDebug("CAT %d, name %s", i, srep_cat_table[i]);
    }
    return 0;
}

static int SRepLoadFile(SRepCIDRTree *cidr_ctx, char *filename)
{
    int r = 0;
    FILE *fp = fopen(filename, "r");

    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening ip rep file %s: %s", filename, strerror(errno));
        return -1;
    }

    r = SRepLoadFileFromFD(cidr_ctx, fp);

    fclose(fp);
    fp = NULL;
    return r;

}

int SRepLoadFileFromFD(SRepCIDRTree *cidr_ctx, FILE *fp)
{
    char line[8192] = "";
    Address a;
    memset(&a, 0x00, sizeof(a));
    a.family = AF_INET;

    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        if (len == 0)
            continue;

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line [0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        while (isspace((unsigned char)line[--len]));

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len == 0)
            continue;

        if (line[len - 1] == '\n' || line[len - 1] == '\r') {
            line[len - 1] = '\0';
        }

        uint8_t cat = 0, value = 0;
        int r = SRepSplitLine(cidr_ctx, line, &a, &cat, &value);
        if (r < 0) {
            SCLogError(SC_ERR_NO_REPUTATION, "bad line \"%s\"", line);
        } else if (r == 0) {
            if (a.family == AF_INET) {
                char ipstr[16];
                PrintInet(AF_INET, (const void *)&a.address, ipstr, sizeof(ipstr));
                SCLogDebug("%s %u %u", ipstr, cat, value);
            } else {
                char ipstr[128];
                PrintInet(AF_INET6, (const void *)&a.address, ipstr, sizeof(ipstr));
                SCLogDebug("%s %u %u", ipstr, cat, value);
            }

            Host *h = HostGetHostFromHash(&a);
            if (h == NULL) {
                SCLogError(SC_ERR_NO_REPUTATION, "failed to get a host, increase host.memcap");
                break;
            } else {
                //SCLogInfo("host %p", h);

                if (h->iprep == NULL) {
                    h->iprep = SCMalloc(sizeof(SReputation));
                    if (h->iprep != NULL) {
                        memset(h->iprep, 0x00, sizeof(SReputation));

                        HostIncrUsecnt(h);
                    }
                }
                if (h->iprep != NULL) {
                    SReputation *rep = h->iprep;

                    /* if version is outdated, it's an older entry that we'll
                     * now replace. */
                    if (rep->version != SRepGetVersion()) {
                        memset(rep, 0x00, sizeof(SReputation));
                    }

                    rep->version = SRepGetVersion();
                    rep->rep[cat] = value;

                    SCLogDebug("host %p iprep %p setting cat %u to value %u",
                        h, h->iprep, cat, value);
#ifdef DEBUG
                    if (SCLogDebugEnabled()) {
                        int i;
                        for (i = 0; i < SREP_MAX_CATS; i++) {
                            if (rep->rep[i] == 0)
                                continue;

                            SCLogDebug("--> host %p iprep %p cat %d to value %u",
                                    h, h->iprep, i, rep->rep[i]);
                        }
                    }
#endif
                }

                HostRelease(h);
            }
        }
    }

    return 0;
}

/**
 *  \brief Create the path if default-rule-path was specified
 *  \param sig_file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */
static char *SRepCompleteFilePath(char *file)
{
    char *defaultpath = NULL;
    char *path = NULL;

    /* Path not specified */
    if (PathIsRelative(file)) {
        if (ConfGet("default-reputation-path", &defaultpath) == 1) {
            SCLogDebug("Default path: %s", defaultpath);
            size_t path_len = sizeof(char) * (strlen(defaultpath) +
                          strlen(file) + 2);
            path = SCMalloc(path_len);
            if (unlikely(path == NULL))
                return NULL;
            strlcpy(path, defaultpath, path_len);
#if defined OS_WIN32 || defined __CYGWIN__
            if (path[strlen(path) - 1] != '\\')
                strlcat(path, "\\\\", path_len);
#else
            if (path[strlen(path) - 1] != '/')
                strlcat(path, "/", path_len);
#endif
            strlcat(path, file, path_len);
       } else {
            path = SCStrdup(file);
            if (unlikely(path == NULL))
                return NULL;
        }
    } else {
        path = SCStrdup(file);
        if (unlikely(path == NULL))
            return NULL;
    }
    return path;
}

/** \brief init reputation
 *
 *  \param de_ctx detection engine ctx for tracking iprep version
 *
 *  \retval 0 ok
 *  \retval -1 error
 *
 *  If this function is called more than once, the category file
 *  is not reloaded.
 */
int SRepInit(DetectEngineCtx *de_ctx)
{
    ConfNode *files;
    ConfNode *file = NULL;
    int r = 0;
    char *sfile = NULL;
    char *filename = NULL;
    int init = 0;
    int i = 0;

    de_ctx->srepCIDR_ctx = (SRepCIDRTree *)SCMalloc(sizeof(SRepCIDRTree));
    if (de_ctx->srepCIDR_ctx == NULL)
        exit(EXIT_FAILURE);
    memset(de_ctx->srepCIDR_ctx, 0, sizeof(SRepCIDRTree));
    SRepCIDRTree *cidr_ctx = de_ctx->srepCIDR_ctx;

    for (i = 0; i < SREP_MAX_CATS; i++) {
        cidr_ctx->srepIPV4_tree[i] = NULL;
        cidr_ctx->srepIPV6_tree[i] = NULL;
    }

    if (SRepGetVersion() == 0) {
        SC_ATOMIC_INIT(srep_eversion);
        init = 1;
    }

    /* if both settings are missing, we assume the user doesn't want ip rep */
    (void)ConfGet("reputation-categories-file", &filename);
    files = ConfGetNode("reputation-files");
    if (filename == NULL && files == NULL) {
        SCLogInfo("IP reputation disabled");
        return 0;
    }

    if (files == NULL) {
        SCLogError(SC_ERR_NO_REPUTATION, "\"reputation-files\" not set");
        return -1;
    }

    if (init) {
        if (filename == NULL) {
            SCLogError(SC_ERR_NO_REPUTATION, "\"reputation-categories-file\" not set");
            return -1;
        }

        /* init even if we have reputation files, so that when we
         * have a live reload, we have inited the cats */
        if (SRepLoadCatFile(filename) < 0) {
            SCLogError(SC_ERR_NO_REPUTATION, "failed to load reputation "
                    "categories file %s", filename);
            return -1;
        }
    }

    de_ctx->srep_version = SRepIncrVersion();
    SCLogDebug("Reputation version %u", de_ctx->srep_version);

    /* ok, let's load signature files from the general config */
    if (files != NULL) {
        TAILQ_FOREACH(file, &files->head, next) {
            sfile = SRepCompleteFilePath(file->val);
            SCLogInfo("Loading reputation file: %s", sfile);

            r = SRepLoadFile(cidr_ctx, sfile);
            if (r < 0){
                if (de_ctx->failure_fatal == 1) {
                    exit(EXIT_FAILURE);
                }
            }
            SCFree(sfile);
        }
    }

    /* Set effective rep version.
     * On live reload we will handle this after de_ctx has been swapped */
    if (init) {
        SRepInitComplete();
    }

    HostPrintStats();
    return 0;
}

void SRepDestroy(DetectEngineCtx *de_ctx) {
    if (de_ctx->srepCIDR_ctx != NULL) {
        int i;
        for (i = 0; i < SREP_MAX_CATS; i++) {
            if (de_ctx->srepCIDR_ctx->srepIPV4_tree[i] != NULL) {
                SCRadixReleaseRadixTree(de_ctx->srepCIDR_ctx->srepIPV4_tree[i]);
                de_ctx->srepCIDR_ctx->srepIPV4_tree[i] = NULL;
            }

            if (de_ctx->srepCIDR_ctx->srepIPV6_tree[i] != NULL) {
                SCRadixReleaseRadixTree(de_ctx->srepCIDR_ctx->srepIPV6_tree[i]);
                de_ctx->srepCIDR_ctx->srepIPV6_tree[i] = NULL;
            }
        }

        SCFree(de_ctx->srepCIDR_ctx);
        de_ctx->srepCIDR_ctx = NULL;
    }
}

#ifdef UNITTESTS

#include "conf-yaml-loader.h"
#include "detect-engine.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int SRepTest01(void)
{
    char str[] = "1.2.3.4,1,2";
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return 0;
    }

    SRepInit(de_ctx);
    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 0) {
        goto end;
    }

    char ipstr[16];
    PrintInet(AF_INET, (const void *)&a.address, ipstr, sizeof(ipstr));

    if (strcmp(ipstr, "1.2.3.4") != 0)
        goto end;

    if (cat != 1)
        goto end;

    if (value != 2)
        goto end;

    result = 1;

end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int SRepTest02(void)
{
    char str[] = "1.1.1.1,";
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return 0;
    }

    SRepInit(de_ctx);
    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) == 0) {
        goto end;
    }
    result = 1;

end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int SRepTest03(void)
{
    char str[] = "1,Shortname,Long Name";

    uint8_t cat = 0;
    char shortname[SREP_SHORTNAME_LEN];

    if (SRepCatSplitLine(str, &cat, shortname, sizeof(shortname)) != 0) {
        printf("split failed: ");
        return 0;
    }

    if (strcmp(shortname, "Shortname") != 0) {
        printf("%s != Shortname: ", shortname);
        return 0;
    }

    if (cat != 1) {
        printf("cat 1 != %u: ", cat);
        return 0;
    }

    return 1;
}

static int SRepTest04(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    SRepInit(de_ctx);

    char str[] = "10.0.0.0/16,1,2";

    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1) {
        goto end;
    }

    result = 1;

end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int SRepTest05(void)
{
    Packet *p = NULL;
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    if (p == NULL) {
        return result;
    }

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");

    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }
    SRepInit(de_ctx);

    char str[] = "10.0.0.0/16,1,20";

    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1) {
        goto end;
    }
    cat = 1;
    value = SRepCIDRGetIPRepSrc(de_ctx->srepCIDR_ctx, p, cat, 0);
    if (value != 20) {
        goto end;
    }
    result = 1;

end:
    UTHFreePacket(p);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int SRepTest06(void)
{
    Packet *p = NULL;
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    if (p == NULL) {
        return result;
    }

    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");

    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }
    SRepInit(de_ctx);

    char str[] =
        "0.0.0.0/0,1,10\n"
        "192.168.0.0/16,2,127";

    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1) {
        goto end;
    }
    cat = 1;
    value = SRepCIDRGetIPRepSrc(de_ctx->srepCIDR_ctx, p, cat, 0);
    if (value != 10) {
        goto end;
    }
    result = 1;

end:
    UTHFreePacket(p);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int SRepTest07(void) {
    char str[] = "2000:0000:0000:0000:0000:0000:0000:0001,";
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return 0;
    }

    SRepInit(de_ctx);
    Address a;
    uint8_t cat = 0, value = 0;
    if (SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) == 0) {
        goto end;
    }
    result = 1;
end:
    DetectEngineCtxFree(de_ctx);
    return result;
}
#endif

/** Global trees that hold host reputation for IPV4 and IPV6 hosts */
IPReputationCtx *rep_ctx;

/**
 * \brief Initialization fuction for the Reputation Context (IPV4 and IPV6)
 *
 * \retval Pointer to the IPReputationCtx created
 *         NULL Error initializing moule;
 */
IPReputationCtx *SCReputationInitCtx(void)
{
    rep_ctx = (IPReputationCtx *)SCMalloc(sizeof(IPReputationCtx));
    if (rep_ctx == NULL)
        return NULL;
    memset(rep_ctx,0,sizeof(IPReputationCtx));

    rep_ctx->reputationIPV4_tree = SCRadixCreateRadixTree(SCReputationFreeData, NULL);
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogDebug("Error initializing Reputation IPV4 module");
        return NULL;
    }

    SCLogDebug("Reputation IPV4 module initialized");

    rep_ctx->reputationIPV6_tree = SCRadixCreateRadixTree(SCReputationFreeData, NULL);
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogDebug("Error initializing Reputation IPV6 module");
        return NULL;
    }

    SCLogDebug("Reputation IPV6 module initialized");
    if (SCMutexInit(&rep_ctx->reputationIPV4_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
        exit(EXIT_FAILURE);
    }
    if (SCMutexInit(&rep_ctx->reputationIPV6_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
        exit(EXIT_FAILURE);
    }

    return rep_ctx;
}


/**
 * \brief Allocates the Reputation structure for a host/netblock
 *
 * \retval rep_data On success, pointer to the rep_data that has to be sent
 *                   along with the key, to be added to the Radix tree
 */
Reputation *SCReputationAllocData(void)
{
    Reputation *rep_data = NULL;

    if ( (rep_data = SCMalloc(sizeof(Reputation))) == NULL)
        return NULL;
    memset(rep_data,0, sizeof(Reputation));
    rep_data->ctime = time(NULL);
    rep_data->mtime= time(NULL);

    return rep_data;
}

/**
 * \brief Used to SCFree the reputation data that is allocated by Reputation API
 *
 * \param Pointer to the data that has to be SCFreed
 */
void SCReputationFreeData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

/**
 * \brief Allocates the Reputation structure for a host/netblock
 *
 * \retval ReputationTransaction pointer On success
 */
ReputationTransaction *SCReputationTransactionAlloc(void)
{
    ReputationTransaction *rtx = NULL;

    if ( (rtx = SCMalloc(sizeof(ReputationTransaction))) == NULL)
        return NULL;
    memset(rtx, 0, sizeof(ReputationTransaction));

    return rtx;
}

/**
 * \brief Used to SCFree the transaction data
 *
 * \param Pointer to the data that has to be SCFreed
 */
void SCReputationTransactionFreeData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

/**
 * \brief Apply the transaction of changes to the reputation
 *        We use transactions because we cant be locking/unlocking the
 *        trees foreach update. This help for a better performance
 *
 * \param rep_data pointer to the reputation to update
 * \param rtx pointer to the transaction data
 */
void SCReputationApplyTransaction(Reputation *rep_data, ReputationTransaction *rtx)
{
    int i = 0;

    /* No modification needed */
    if ( !(rtx->flags & TRANSACTION_FLAG_NEEDSYNC))
        return;

    /* Here we should apply a formula, a threshold or similar,
     * maybe values loaded from config */
    for (; i < REPUTATION_NUMBER; i++) {
        if (rtx->flags & TRANSACTION_FLAG_INCS) {
            if (rep_data->reps[i] + rtx->inc[i] < 255)
                rep_data->reps[i] += rtx->inc[i];
            else
                rep_data->reps[i] = 255;
        }
        if (rtx->flags & TRANSACTION_FLAG_DECS) {
            if (rep_data->reps[i] - rtx->dec[i] > 0)
                rep_data->reps[i] -= rtx->dec[i];
            else
                rep_data->reps[i] = 0;
        }
    }
    rep_data->mtime = time(NULL);
    rep_data->flags |= REPUTATION_FLAG_NEEDSYNC;
}

/**
 * \brief Function that compare two reputation structs to determine if they are equal
 *
 * \param rep1 pointer to reputation 1
 * \param rep2 pointer to reputation 2
 *
 * \retval 1 if they are equal; 0 if not
 */
int SCReputationEqual(Reputation *rep1, Reputation *rep2)
{
    return (memcmp(rep1->reps, rep2->reps, REPUTATION_NUMBER * sizeof(uint8_t)) == 0)? 1 : 0;
}


/**
 * \brief Helper function to print the Reputation structure
 *
 * \param Pointer rep_data to a Reputation structure
 */
void SCReputationPrint(Reputation *rep_data)
{
    if (rep_data == NULL) {
        printf("No Reputation Data!\n");
        return;
    }
    int i = 0;
    for (; i < REPUTATION_NUMBER; i++)
        printf("Rep_type %d = %d\n", i, rep_data->reps[i]);

    if (rep_data->flags & REPUTATION_FLAG_NEEDSYNC)
        printf("REPUTATION_FLAG_NEEDSYNC = 1\n");
}

/**
 * \brief Clone all the data of a reputation
 *        When you try to update the feed, if the data you have belongs
 *        to a netblock, it will be cloned and inserted or a host, with
 *        the modifications that you add
 *
 * \param orig Pointer to the original reputation (probably of a netblock)
 *
 * \retval Reputation Pointer to the reputation copy
 */
Reputation *SCReputationClone(Reputation *orig)
{
    Reputation *rep = NULL;
    if (orig == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    if ( (rep = SCMalloc(sizeof(Reputation))) == NULL)
        return NULL;
    memcpy(rep, orig, sizeof(Reputation));
    return rep;
}

void SCReputationFreeCtx(IPReputationCtx *rep_ctx)
{
    if (rep_ctx->reputationIPV4_tree != NULL) {
        SCRadixReleaseRadixTree(rep_ctx->reputationIPV4_tree);
        rep_ctx->reputationIPV4_tree = NULL;
        SCMutexDestroy(&rep_ctx->reputationIPV4_lock);
    }
    if (rep_ctx->reputationIPV6_tree != NULL) {
        SCRadixReleaseRadixTree(rep_ctx->reputationIPV6_tree);
        rep_ctx->reputationIPV6_tree = NULL;
        SCMutexDestroy(&rep_ctx->reputationIPV6_lock);
    }
}

/**
 * \brief Used to add a new reputation to the reputation module (only at the startup)
 *
 * \param ipv4addr pointer to the ipv4 address key
 * \param netmask_value of the ipv4 address (can be a subnet or a host (32))
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure; rep_data on success
 */
Reputation *SCReputationAddIPV4Data(uint8_t *ipv4addr, int netmask_value, Reputation *rep_data)
{
    struct in_addr *ipv4_addr = (struct in_addr *) ipv4addr;

    if (ipv4_addr == NULL || rep_data == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    if (netmask_value == 32) {
        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV4_lock);
        SCRadixAddKeyIPV4((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
                  (void *)rep_data);
        SCMutexUnlock(&rep_ctx->reputationIPV4_lock);

    } else {
        if (netmask_value < 0 || netmask_value > 31) {
            SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "Invalid IPV4 Netblock");
            return NULL;
        }

        MaskIPNetblock((uint8_t *)ipv4_addr, netmask_value, 32);

        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV4_lock);
        SCRadixAddKeyIPV4Netblock((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
                      (void *)rep_data, netmask_value);
        SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    }

    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (exact match), given an ipv4 address in the raw
 *        address format.
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4ExactMatch(uint8_t *ipv4_addr)
{
    Reputation *rep_data = NULL;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4ExactMatch(ipv4_addr, rep_ctx->reputationIPV4_tree, &user_data);
    if (user_data == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)user_data);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (best match), given an ipv4 address in the raw
 *        address format.
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4BestMatch(uint8_t *ipv4_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(ipv4_addr, rep_ctx->reputationIPV4_tree, &user_data);
    if (user_data == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)user_data);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (best match), given an ipv6 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6BestMatch(uint8_t *ipv6_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6BestMatch(ipv6_addr, rep_ctx->reputationIPV6_tree, &user_data);
    if (user_data == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)user_data);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (exact match), given an ipv6 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to a copy of the host reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6ExactMatch(uint8_t *ipv6_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6ExactMatch(ipv6_addr, rep_ctx->reputationIPV6_tree, &user_data);
    if (user_data == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)user_data);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    return rep_data;
}


/**
 * \brief Retrieves the Real Reputation of a host (exact match), given an ipv4 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4ExactMatchReal(uint8_t *ipv4_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4ExactMatch(ipv4_addr, rep_ctx->reputationIPV4_tree, &user_data);
    if (user_data == NULL) {
        return NULL;
    } else {
        return (Reputation *)user_data;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (best match), given an ipv4 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4BestMatchReal(uint8_t *ipv4_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(ipv4_addr, rep_ctx->reputationIPV4_tree, &user_data);
    if (user_data == NULL) {
        return NULL;
    } else {
        return (Reputation *)user_data;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (best match), given an ipv6 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6BestMatchReal(uint8_t *ipv6_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6BestMatch(ipv6_addr, rep_ctx->reputationIPV6_tree, &user_data);
    if (user_data == NULL) {
        return NULL;
    } else {
        return (Reputation *)user_data;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (exact match), given an ipv6 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6ExactMatchReal(uint8_t *ipv6_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6ExactMatch(ipv6_addr, rep_ctx->reputationIPV6_tree, &user_data);
    if (user_data == NULL) {
        return NULL;
    } else {
        return (Reputation *)user_data;
    }
}

/**
 * \brief Remove the node of the reputation tree associated to the ipv4 address
 *
 * \param ipv4_addr Pointer to a raw ipv4 address
 * \param netmask_value netmask to apply to the address (32 for host)
 *
 */
void SCReputationRemoveIPV4Data(uint8_t * ipv4_addr, uint8_t netmask_value)
{
    SCMutexLock(&rep_ctx->reputationIPV4_lock);
    SCRadixRemoveKeyIPV4Netblock(ipv4_addr, rep_ctx->reputationIPV4_tree, netmask_value);
    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
}

/**
 * \brief Remove the node of the reputation tree associated to the ipv6 address
 *
 * \param ipv6_addr Pointer to a raw ipv6 address
 * \param netmask_value netmask to apply to the address (128 for host)
 *
 */
void SCReputationRemoveIPV6Data(uint8_t * ipv6_addr, uint8_t netmask_value)
{
    SCMutexLock(&rep_ctx->reputationIPV6_lock);
    SCRadixRemoveKeyIPV6Netblock(ipv6_addr, rep_ctx->reputationIPV6_tree, netmask_value);
    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
}

/**
 * \brief Used to add a new reputation to the reputation module (only at the startup)
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param netmask_value of the ipv6 address (can be a subnet)
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationAddIPV6Data(uint8_t *ipv6addr, int netmask_value, Reputation *rep_data)
{
    struct in_addr *ipv6_addr = (struct in_addr *) ipv6addr;

    if (ipv6_addr == NULL || rep_data == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    if (netmask_value == 128) {
        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV6_lock);
        SCRadixAddKeyIPV6((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
                  (void *)rep_data);
        SCMutexUnlock(&rep_ctx->reputationIPV6_lock);

    } else {
        if (netmask_value < 0 || netmask_value > 127) {
            SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "Invalid IPV6 Netblock");
            return NULL;
        }

        MaskIPNetblock((uint8_t *)ipv6_addr, netmask_value, 128);

        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV6_lock);
        SCRadixAddKeyIPV6Netblock((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
                      (void *)rep_data, netmask_value);
        SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    }

    return rep_data;
}

/**
 * \brief Update a reputation or insert a new one. If it doesn't exist
 *        it will try to search for the reputation of parent subnets to
 *        create the new reputation data based on this one
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationUpdateIPV4Data(uint8_t *ipv4addr, ReputationTransaction *rtx)
{
    struct in_addr *ipv4_addr = (struct in_addr *) ipv4addr;
    Reputation *actual_rep;

    if (ipv4_addr == NULL || rtx == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    /* Be careful with the mutex */
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    /* Search exact match and update */
    actual_rep = SCReputationLookupIPV4ExactMatchReal(ipv4addr);
    if (actual_rep == NULL) {
        /* else search best match (parent subnets) */
        actual_rep =SCReputationLookupIPV4BestMatchReal(ipv4addr);

        if (actual_rep != NULL) {
            /* clone from parent and insert host */
            actual_rep = SCReputationClone(actual_rep);
        } else {
            /* else insert a new reputation data for the host */
            actual_rep = SCReputationAllocData();
            /* If new, we only increment values */
            rtx->flags = TRANSACTION_FLAG_INCS;
            rtx->flags |= TRANSACTION_FLAG_NEEDSYNC;
        }

        /* insert the reputation data in the tree */
        SCRadixAddKeyIPV4((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
              (void *)actual_rep);
    }
    /* Apply updates */
    SCReputationApplyTransaction(actual_rep, rtx);

    /* Unlock! */
    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);

    return actual_rep;
}

/**
 * \brief Update a reputation or insert a new one. If it doesn't exist
 *        it will try to search for the reputation of parent subnets to
 *        create the new reputation data based on this one
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationUpdateIPV6Data(uint8_t *ipv6addr, ReputationTransaction *rtx)
{
    struct in_addr *ipv6_addr = (struct in_addr *) ipv6addr;
    Reputation *actual_rep;

    if (ipv6_addr == NULL || rtx == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    /* Be careful with the mutex */
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    /* Search exact match and update */
    actual_rep = SCReputationLookupIPV6ExactMatchReal(ipv6addr);
    if (actual_rep == NULL) {
        /* else search best match (parent subnets) */
        actual_rep =SCReputationLookupIPV6BestMatchReal(ipv6addr);

        if (actual_rep != NULL) {
            /* clone from parent and insert host */
            actual_rep = SCReputationClone(actual_rep);
        } else {
            /* else insert a new reputation data for the host */
            actual_rep = SCReputationAllocData();
            /* If new, we only increment values */
            rtx->flags = TRANSACTION_FLAG_INCS;
            rtx->flags |= TRANSACTION_FLAG_NEEDSYNC;
        }

        /* insert the reputation data in the tree */
        SCRadixAddKeyIPV6((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
              (void *)actual_rep);
    }
    /* Apply updates */
    SCReputationApplyTransaction(actual_rep, rtx);

    /* Unlock! */
    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);

    return actual_rep;
}


/* ----------------- UNITTESTS-------------------- */
#ifdef UNITTESTS

/**
 * \test Adding (from numeric ipv4) and removing host reputation in the Reputation context
 *       tree. THe reputation data is the real one, no copies here.
 */
int SCReputationTestIPV4AddRemoveHost01(void)
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 31, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || rep_data == rep_orig)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.8", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data != NULL)
        goto error;


    /* Removing */
    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    SCReputationRemoveIPV4Data((uint8_t *) &in, 32);

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
        goto error;

    SCReputationRemoveIPV4Data((uint8_t *) &in, 32);
    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv6) and removing host reputation in the Reputation context
 *       tree. THe reputation data is the real one, no copies here.
 */
int SCReputationTestIPV6AddRemoveHost01(void)
{
    uint8_t in[16];
    uint8_t i = 0;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
         goto error;

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 1;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 8;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);

    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 127, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || rep_data == rep_orig)
        goto error;


    /* Removing */
    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    SCReputationRemoveIPV6Data((uint8_t *) &in, 128);

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
        goto error;

    SCReputationRemoveIPV6Data((uint8_t *) &in, 128);
    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv4) and retrieving reputations
 *       tree. The reputation data retireved are copies of the original.
 */
int SCReputationTestIPV4AddRemoveHost02(void)
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 9;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 31, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv6) and removing host reputation in the Reputation context
 *       tree. The reputation data retireved are copies of the original.
 */
int SCReputationTestIPV6AddRemoveHost02(void)
{
    int i = 0;
    uint8_t in[16];

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;
    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 9;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 127, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 1)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2364", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Test searches (best and exact matches)
 */
int SCReputationTestIPV4BestExactMatch01(void)
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_origC = NULL;
    Reputation *rep_origB = NULL;
    Reputation *rep_origA = NULL;

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    /* adding a host */
    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;
    Reputation *rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    /* Adding C subnet */
    if (inet_pton(AF_INET, "192.168.1.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origC = SCReputationAddIPV4Data((uint8_t *) &in, 24, rep_orig);
    if (rep_origC == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    rep_orig = SCReputationAllocData();
    /* Adding B subnet */
    if (inet_pton(AF_INET, "192.168.0.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origB = SCReputationAddIPV4Data((uint8_t *) &in, 16, rep_orig);
    if (rep_origB == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    if (inet_pton(AF_INET, "192.168.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origB)
        goto error;

    rep_orig = SCReputationAllocData();
    /* Adding A subnet */
    if (inet_pton(AF_INET, "192.0.0.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origA = SCReputationAddIPV4Data((uint8_t *) &in, 8, rep_orig);
    if (rep_origA == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    if (inet_pton(AF_INET, "192.168.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origB)
        goto error;

    if (inet_pton(AF_INET, "192.167.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origA)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;
error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Update transactions
 */
int SCReputationTestIPV4Update01(void)
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();

    ReputationTransaction rtx;
    memset(&rtx, 0, sizeof(ReputationTransaction));
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_orig->reps[i] = 10;
    }

    if (inet_pton(AF_INET, "192.168.0.0", &in) < 0)
         goto error;

    /* Add add it as net */
    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 16, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rtx.dec[REPUTATION_DDOS] = 5;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 30;
    rtx.flags |= TRANSACTION_FLAG_NEEDSYNC;
    rtx.flags |= TRANSACTION_FLAG_INCS;
    rtx.flags |= TRANSACTION_FLAG_DECS;

    if (inet_pton(AF_INET, "192.168.10.100", &in) < 0)
         goto error;

    /* Update (it will create the host entry with the data of the net) */
    SCReputationUpdateIPV4Data((uint8_t *)&in, &rtx);

    /* Create the reputation that any host 192.168.* should have */
    Reputation *rep_aux = SCReputationAllocData();

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_aux->reps[i] = 10;
    }

    rep_aux->reps[REPUTATION_DDOS] = 5;
    rep_aux->reps[REPUTATION_PHISH] = 60;
    rep_aux->reps[REPUTATION_MALWARE] = 40;

    Reputation *rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* Now that is created, it should update only the host */
    rtx.dec[REPUTATION_DDOS] = 50;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 50;

    rep_aux->reps[REPUTATION_DDOS] = 0;
    rep_aux->reps[REPUTATION_PHISH] = 110;
    rep_aux->reps[REPUTATION_MALWARE] = 90;

    SCReputationUpdateIPV4Data((uint8_t *)&in, &rtx);

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* So let's see if we add a host and get the parent data again */
    if (inet_pton(AF_INET, "192.168.10.101", &in) < 0)
         goto error;

    rep_aux->reps[REPUTATION_DDOS] = 10;
    rep_aux->reps[REPUTATION_PHISH] = 10;
    rep_aux->reps[REPUTATION_MALWARE] = 10;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);

    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Update transactions
 */
int SCReputationTestIPV6Update01(void)
{
    int i = 0;
    uint8_t in[16];

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();

    ReputationTransaction rtx;
    memset(&rtx, 0, sizeof(ReputationTransaction));
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_orig->reps[i] = 10;
    }

    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1DDD", &in) < 0)
         goto error;

    /* Add add it as net */
    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 98, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rtx.dec[REPUTATION_DDOS] = 5;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 30;
    rtx.flags |= TRANSACTION_FLAG_NEEDSYNC;
    rtx.flags |= TRANSACTION_FLAG_INCS;
    rtx.flags |= TRANSACTION_FLAG_DECS;

    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1ABA", &in) < 0)
         goto error;

    /* Update (it will create the host entry with the data of the net) */
    SCReputationUpdateIPV6Data((uint8_t *)&in, &rtx);

    /* Create the reputation that any host 192.168.* should have */
    Reputation *rep_aux = SCReputationAllocData();

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_aux->reps[i] = 10;
    }

    rep_aux->reps[REPUTATION_DDOS] = 5;
    rep_aux->reps[REPUTATION_PHISH] = 60;
    rep_aux->reps[REPUTATION_MALWARE] = 40;

    Reputation *rep_data = SCReputationLookupIPV6BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* Now that is created, it should update only the host */
    rtx.dec[REPUTATION_DDOS] = 50;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 50;

    rep_aux->reps[REPUTATION_DDOS] = 0;
    rep_aux->reps[REPUTATION_PHISH] = 110;
    rep_aux->reps[REPUTATION_MALWARE] = 90;

    SCReputationUpdateIPV6Data((uint8_t *)&in, &rtx);

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* So let's see if we add a host and get the parent data again */
    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1ACB", &in) < 0)
         goto error;

    rep_aux->reps[REPUTATION_DDOS] = 10;
    rep_aux->reps[REPUTATION_PHISH] = 10;
    rep_aux->reps[REPUTATION_MALWARE] = 10;

    rep_data = SCReputationLookupIPV6BestMatchReal((uint8_t *) &in);


    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

#endif /* UNITTESTS */

/** Register the following unittests for the Reputation module */
void SCReputationRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCReputationTestIPV4AddRemoveHost01",
                   SCReputationTestIPV4AddRemoveHost01, 1);
    UtRegisterTest("SCReputationTestIPV6AddRemoveHost01",
                   SCReputationTestIPV6AddRemoveHost01, 1);

    UtRegisterTest("SCReputationTestIPV4BestExactMatch01",
                   SCReputationTestIPV4BestExactMatch01, 1);

    UtRegisterTest("SCReputationTestIPV4AddRemoveHost02",
                   SCReputationTestIPV4AddRemoveHost02, 1);
    UtRegisterTest("SCReputationTestIPV6AddRemoveHost02",
                   SCReputationTestIPV6AddRemoveHost02, 1);

    UtRegisterTest("SCReputationTestIPV4Update01",
                   SCReputationTestIPV4Update01, 1);
    UtRegisterTest("SCReputationTestIPV6Update01",
                   SCReputationTestIPV6Update01, 1);

    UtRegisterTest("SRepTest01", SRepTest01, 1);
    UtRegisterTest("SRepTest02", SRepTest02, 1);
    UtRegisterTest("SRepTest03", SRepTest03, 1);
    UtRegisterTest("SRepTest04", SRepTest04, 1);
    UtRegisterTest("SRepTest05", SRepTest05, 1);
    UtRegisterTest("SRepTest06", SRepTest06, 1);
    UtRegisterTest("SRepTest07", SRepTest07, 1);
#endif /* UNITTESTS */
}

