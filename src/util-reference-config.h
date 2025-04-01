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

#ifndef SURICATA_UTIL_REFERENCE_CONFIG_H
#define SURICATA_UTIL_REFERENCE_CONFIG_H

#include "detect.h"

#define REFERENCE_SYSTEM_NAME_MAX   64
#define REFERENCE_CONTENT_NAME_MAX  1024

/**
 * \brief Holds a reference from the file - reference.config.
 */
typedef struct SCRConfReference_ {
    /* The system name.  This is the primary key for a reference. */
    char *system;
    /* The url for the above reference */
    char *url;
} SCRConfReference;

SCRConfReference *SCRConfAllocSCRConfReference(const char *, const char *);
void SCRConfDeAllocSCRConfReference(SCRConfReference *);
int SCRConfLoadReferenceConfigFile(DetectEngineCtx *, FILE *);
void SCRConfDeInitContext(DetectEngineCtx *);
SCRConfReference *SCRConfGetReference(const char *,
                                      DetectEngineCtx *);
int SCRConfAddReference(DetectEngineCtx *de_ctx, const char *line);
void SCRConfRegisterTests(void);

/* these below functions are only used by unittests */
FILE *SCRConfGenerateValidDummyReferenceConfigFD01(void);
FILE *SCRConfGenerateInvalidDummyReferenceConfigFD02(void);
FILE *SCRConfGenerateInvalidDummyReferenceConfigFD03(void);

void SCReferenceSCConfInit(DetectEngineCtx *de_ctx);
void SCReferenceConfDeinit(DetectEngineCtx *de_ctx);

#endif /* SURICATA_UTIL_REFERENCE_CONFIG_H */
