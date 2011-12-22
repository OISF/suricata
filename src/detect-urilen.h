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
 * \author Gurvinder Singh <gurvindersighdahiya@gmail.com>
 */

#ifndef _DETECT_URILEN_H
#define	_DETECT_URILEN_H

#define DETECT_URILEN_LT   0   /**< "less than" operator */
#define DETECT_URILEN_GT   1   /**< "greater than" operator */
#define DETECT_URILEN_RA   2   /**< range operator */
#define DETECT_URILEN_EQ   3   /**< equal operator */

typedef struct DetectUrilenData_ {
    uint16_t urilen1;   /**< 1st Uri Length value in the signature*/
    uint16_t urilen2;   /**< 2nd Uri Length value in the signature*/
    uint8_t mode;   /**< operator used in the signature */
    uint8_t raw_buffer;
}DetectUrilenData;

int DetectUrilenMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                       uint8_t, void *, Signature *, SigMatch *);
void DetectUrilenRegister(void);

#endif	/* _DETECT_URILEN_H */

