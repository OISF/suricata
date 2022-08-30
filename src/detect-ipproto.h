/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DETECT_IPPROTO_H__
#define __DETECT_IPPROTO_H__

/** IPProto Operators */
#define DETECT_IPPROTO_OP_EQ     '=' /**< "equals" operator (default) */
#define DETECT_IPPROTO_OP_NOT    '!' /**< "not" operator */
#define DETECT_IPPROTO_OP_LT     '<' /**< "less than" operator */
#define DETECT_IPPROTO_OP_GT     '>' /**< "greater than" operator */

/** ip_proto data */
typedef struct DetectIPProtoData_ {
    uint8_t op;                       /**< Operator used to compare */
    uint8_t proto;                    /**< Protocol used to compare */
} DetectIPProtoData;

/* prototypes */

/**
 * \brief Registration function for ip_proto keyword.
 */
void DetectIPProtoRegister (void);
void DetectIPProtoRemoveAllSMs(DetectEngineCtx *, Signature *);

#endif /* __DETECT_IPPROTO_H__ */

