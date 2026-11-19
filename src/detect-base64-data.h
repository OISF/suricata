/* Copyright (C) 2015 Open Information Security Foundation
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
 * `base64_data` rule keyword: following content matches inspect the
 * buffer decoded by a preceding `base64_decode`.
 */

#ifndef SURICATA_DETECT_BASE64_DATA_H
#define SURICATA_DETECT_BASE64_DATA_H

/** \brief Register the `base64_data` keyword in sigmatch_table. */
void DetectBase64DataRegister(void);

#endif /* SURICATA_DETECT_BASE64_DATA_H */
