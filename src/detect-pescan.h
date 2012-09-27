/* Copyright (C) 2012 BAE Systems
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 */

#ifndef __DETECT_PESCAN_H__
#define __DETECT_PESCAN_H__

typedef enum {
    DETECT_PESCAN_ANY = 0,  /**< match on any score (default) */
    DETECT_PESCAN_LT,       /**< "less than" operator */
    DETECT_PESCAN_LTEQ,     /**< "less than or equal to" operator */
    DETECT_PESCAN_EQ,       /**< "equals" operator (default no op) */
    DETECT_PESCAN_GT,       /**< "greater than" operator */
    DETECT_PESCAN_GTEQ,     /**< "greater than or equal to" operator */
    DETECT_PESCAN_RA,       /**< "range excluding" operator */
    DETECT_PESCAN_RAEQ,     /**< "range including" operator */
} DetectPescanMode;

/**
 * \struct DetectPescanData
 *
 * Structure containing the rule 'options' data that is to be used to
 * match against the file provided by the match function.
 */
typedef struct DetectPescanData_ {
    double score1; /**< first score threshold for a match (required) */
    double score2; /**< second score threshold for a match (optional) */
    uint8_t mode; /**< mode of comparison */
    int thread_ctx_id; /**< thread context id for local storage */
} DetectPescanData;

/* prototypes */
void DetectPescanRegister (void);

#endif /* __DETECT_PESCAN_H__ */
