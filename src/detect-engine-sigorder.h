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

#ifndef __DETECT_ENGINE_SIGORDER_H__
#define __DETECT_ENGINE_SIGORDER_H__

/**
 * \brief Different kinds of helper data that can be used by the signature
 *        ordering module.  Used by the "user" field in SCSigSignatureWrapper
 */
typedef enum{
    SC_RADIX_USER_DATA_FLOWBITS,
    SC_RADIX_USER_DATA_FLOWVAR,
    SC_RADIX_USER_DATA_PKTVAR,
    SC_RADIX_USER_DATA_FLOWINT,
    SC_RADIX_USER_DATA_HOSTBITS,
    SC_RADIX_USER_DATA_IPPAIRBITS,
    SC_RADIX_USER_DATA_MAX
} SCRadixUserDataType;

/**
 * \brief Signature wrapper used by signature ordering module while ordering
 *        signatures
 */
typedef struct SCSigSignatureWrapper_ {
    /* the wrapped signature */
    Signature *sig;

    /* used as the lower limit SCSigSignatureWrapper that is used by the next
     * ordering function, which will order the incoming Sigwrapper after this
     * (min) wrapper */
    struct SCSigSignatureWrapper_ *min;
    /* used as the upper limit SCSigSignatureWrapper that is used by the next
     * ordering function, which will order the incoming Sigwrapper below this
     * (max) wrapper */
    struct SCSigSignatureWrapper_ *max;

    /* user data that is to be associated with this sigwrapper */
    int user[SC_RADIX_USER_DATA_MAX];

    struct SCSigSignatureWrapper_ *next;
    struct SCSigSignatureWrapper_ *prev;
} SCSigSignatureWrapper;

/**
 * \brief Structure holding the signature ordering function used by the
 *        signature ordering module
 */
typedef struct SCSigOrderFunc_ {
    /* Pointer to the Signature Ordering function */
    int (*SWCompare)(SCSigSignatureWrapper *sw1, SCSigSignatureWrapper *sw2);

    struct SCSigOrderFunc_ *next;
} SCSigOrderFunc;

void SCSigOrderSignatures(DetectEngineCtx *);
void SCSigRegisterSignatureOrderingFuncs(DetectEngineCtx *);
void SCSigRegisterSignatureOrderingTests(void);
void SCSigSignatureOrderingModuleCleanup(DetectEngineCtx *);

#endif /* __DETECT_ENGINE_SIGORDER_H__ */
