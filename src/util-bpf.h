/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __UTIL_BPF_H__
#define __UTIL_BPF_H__

#if !defined __OpenBSD__

int SCBPFCompile(int snaplen_arg, int linktype_arg, struct bpf_program *program,
                 const char *buf, int optimize, uint32_t mask,
                 char *errbuf, size_t errbuf_len);

void SCBPFFree(struct bpf_program *program);

#endif /* Not __OpenBSD__ */
#endif /* __UTIL_BPF_H__ */
