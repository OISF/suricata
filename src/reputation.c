/* Copyright (C) 2007-2019 Open Information Security Foundation
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

#include "suricata-common.h"
#include "reputation.h"
#include "threads.h"
#include "conf.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-ip.h"
#include "util-path.h"
#include "util-print.h"
#include "util-unittest.h"
#include "util-validate.h"

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

static void SRepCIDRAddNetblock(SRepCIDRTree *cidr_ctx, char *ip, int cat, uint8_t value)
{
    SReputation *user_data = NULL;
    if ((user_data = SCMalloc(sizeof(SReputation))) == NULL) {
        FatalError(SC_ERR_FATAL, "Error allocating memory. Exiting");
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

void SRepFreeHostData(Host *h)
{
    SCFree(h->iprep);
    h->iprep = NULL;
    DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(h->use_cnt) != 1);
    HostDecrUsecnt(h);
}

/** \brief Set effective reputation version after
 *         reputation initialization is complete. */
static void SRepInitComplete(void)
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
        SRepFreeHostData(h);
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

    int c;
    if (StringParseI32RangeCheck(&c, 10, 0, (const char *)ptrs[0], 0, SREP_MAX_CATS - 1) < 0)
        return -1;

    *cat = (uint8_t)c;
    strlcpy(shortname, ptrs[1], shortname_len);
    return 0;

}

/**
 *  \retval 0 valid
 *  \retval 1 header
 *  \retval -1 bad line
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

    uint8_t c, v;
    if (StringParseU8RangeCheck(&c, 10, 0, (const char *)ptrs[1], 0, SREP_MAX_CATS - 1) < 0)
        return -1;

    if (StringParseU8RangeCheck(&v, 10, 0, (const char *)ptrs[2], 0, SREP_MAX_VAL) < 0)
        return -1;

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

uint8_t SRepCatGetByShortname(char *shortname)
{
    uint8_t cat;
    for (cat = 0; cat < SREP_MAX_CATS; cat++) {
        if (strcmp(srep_cat_table[cat], shortname) == 0)
            return cat;
    }

    return 0;
}

static int SRepLoadCatFile(const char *filename)
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

        Address a;
        memset(&a, 0x00, sizeof(a));
        a.family = AF_INET;

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
    const char *defaultpath = NULL;
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
    const char *filename = NULL;
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
        SCLogConfig("IP reputation disabled");
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

    /* ok, let's load reputation files from the general config */
    if (files != NULL) {
        TAILQ_FOREACH(file, &files->head, next) {
            char *sfile = SRepCompleteFilePath(file->val);
            if (sfile) {
                SCLogInfo("Loading reputation file: %s", sfile);

                int r = SRepLoadFile(cidr_ctx, sfile);
                if (r < 0){
                    if (de_ctx->failure_fatal == 1) {
                        exit(EXIT_FAILURE);
                    }
                }
                SCFree(sfile);
            }
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
#include "tests/reputation.c"
#endif
