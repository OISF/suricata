/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 */

#ifndef __APP_LAYER_HTP_XFF_H__
#define __APP_LAYER_HTP_XFF_H__

int GetXFFIPFromTx(const Packet *p, uint64_t tx_id, char *xff_header, char *dstbuf, int dstbuflen);

int GetXFFIP(const Packet *p, char *xff_header, char *dstbuf, int dstbuflen);

#endif /* __APP_LAYER_HTP_XFF_H__ */
