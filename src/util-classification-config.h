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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_CLASSIFICATION_CONFIG_H__
#define __UTIL_CLASSIFICATION_CONFIG_H__

#define CLASSTYPE_NAME_MAX_LEN 64
#define CLASSTYPE_DESC_MAX_LEN 512

/**
 * \brief Container for a Classtype from the Classification.config file.
 */
typedef struct SCClassConfClasstype_ {
    /* The index of the classification within classification.config */
    uint16_t classtype_id;

    /* The priority this classification type carries */
    int priority;

    /* The classtype name.  This is the primary key for a Classification. */
    char *classtype;

    /* Description for a classification.  Would be used while printing out
     * the classification info for a Signature, by the fast-log module. */
    char *classtype_desc;
} SCClassConfClasstype;

bool SCClassConfLoadClassificationConfigFile(DetectEngineCtx *, FILE *fd);
int SCClassConfAddClasstype(DetectEngineCtx *de_ctx, char *rawstr, uint16_t index);
SCClassConfClasstype *SCClassConfGetClasstype(const char *,
                                              DetectEngineCtx *);
void SCClassConfDeInitContext(DetectEngineCtx *);

void SCClassConfInit(void);
void SCClassConfDeinit(void);

/* for unittests */
#ifdef UNITTESTS
void SCClassConfRegisterTests(void);
FILE *SCClassConfGenerateValidDummyClassConfigFD01(void);
FILE *SCClassConfGenerateInvalidDummyClassConfigFD02(void);
FILE *SCClassConfGenerateInvalidDummyClassConfigFD03(void);
#endif

#endif /* __UTIL_CLASSIFICATION_CONFIG_H__ */
