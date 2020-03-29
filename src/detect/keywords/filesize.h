/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_FILESIZE_H__
#define	__DETECT_FILESIZE_H__

#define DETECT_FILESIZE_LT   0   /**< "less than" operator */
#define DETECT_FILESIZE_GT   1   /**< "greater than" operator */
#define DETECT_FILESIZE_RA   2   /**< range operator */
#define DETECT_FILESIZE_EQ   3   /**< equal operator */

typedef struct DetectFilesizeData_ {
    uint64_t size1;     /**< 1st value in the signature*/
    uint64_t size2;     /**< 2nd value in the signature*/
    uint8_t mode;       /**< operator used in the signature */
} DetectFilesizeData;

//int DetectFilesizeMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
//                       uint8_t, void *, Signature *, SigMatch *);
void DetectFilesizeRegister(void);

#endif	/* _DETECT_URILEN_H */
