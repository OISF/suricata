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
 * \author Victor Julien <victor@inliniac.net>
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Unit test framework
 */

#ifndef __UTIL_UNITTEST_H__
#define __UTIL_UNITTEST_H__

#ifdef UNITTESTS

typedef struct UtTest_ {

    char *name;
    int(*TestFn)(void);
    int evalue;

    struct UtTest_ *next;

} UtTest;


void UtRegisterTest(char *name, int(*TestFn)(void), int evalue);
uint32_t UtRunTests(char *regex_arg);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (char *regex_arg);
void UtListTests(char *regex_arg);
void UtRunModeRegister(void);

#endif

#endif /* __UTIL_UNITTEST_H__ */

