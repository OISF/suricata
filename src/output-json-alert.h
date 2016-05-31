/* Copyright (C) 2013-2014 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Logs alerts in JSON format.
 *
 */

#ifndef __OUTPUT_JSON_ALERT_H__
#define __OUTPUT_JSON_ALERT_H__

void JsonAlertLogRegister(void);
#ifdef HAVE_LIBJANSSON
#define LOG_JSON_PAYLOAD            BIT_U32(1)
#define LOG_JSON_PACKET             BIT_U32(2)
#define LOG_JSON_PAYLOAD_BASE64     BIT_U32(3)
#define LOG_JSON_HTTP               BIT_U32(4)
#define LOG_JSON_TLS                BIT_U32(5)
#define LOG_JSON_SSH                BIT_U32(6)
#define LOG_JSON_SMTP               BIT_U32(7)
#define LOG_JSON_TAGGED_PACKETS     BIT_U32(8)
#define LOG_JSON_HTTP_BODY          BIT_U32(9)
#define LOG_JSON_HTTP_BODY_BASE64   BIT_U32(10)
#define LOG_JSON_DNP3               BIT_U32(11)
#define LOG_JSON_VARS               BIT_U32(12)

void AlertJsonHeader(const Packet *p, const PacketAlert *pa, json_t *js);
#endif /* HAVE_LIBJANSSON */

#endif /* __OUTPUT_JSON_ALERT_H__ */

