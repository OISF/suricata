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

/**
 * \addtogroup Testing
 *
 * @{
 */

#ifndef __UTIL_UNITTEST_H__
#define __UTIL_UNITTEST_H__

#ifdef UNITTESTS

typedef struct UtTest_
{
    const char *name;
    int(*TestFn)(void);

    struct UtTest_ *next;

} UtTest;

void UtRegisterTest(const char *name, int(*TestFn)(void));
uint32_t UtRunTests(const char *regex_arg);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (const char *regex_arg);
void UtListTests(const char *regex_arg);
void UtRunModeRegister(void);

extern int unittests_fatal;

/**
 * \breif Fail a test.
 */
#define FAIL do {                                      \
        if (unittests_fatal) {                         \
            BUG_ON(1);                                 \
        } else {                                       \
            return 0;                                  \
        }                                              \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to false.
 */
#define FAIL_IF(expr) do {                             \
        if (unittests_fatal) {                         \
            BUG_ON(expr);                              \
        } else if (expr) {                             \
            return 0;                                  \
        }                                              \
    } while (0)

/**
 * \brief Fail a test if expression to true.
 */
#define FAIL_IF_NOT(expr) do { \
        FAIL_IF(!(expr));      \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to NULL.
 */
#define FAIL_IF_NULL(expr) do {                 \
        FAIL_IF(NULL == expr);                  \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to non-NULL.
 */
#define FAIL_IF_NOT_NULL(expr) do { \
        FAIL_IF(NULL != expr);      \
    } while (0)

/**
 * \brief Pass the test.
 *
 * Only to be used at the end of a function instead instead of "return 1."
 */
#define PASS do { \
        return 1; \
    } while (0)

#endif

/**
 * \brief Pass the test if expression evaluates to true.
 *
 * Only to be used at the end of a function instead of returning the
 * result of an expression.
 */
#define PASS_IF(expr) do { \
        FAIL_IF(!(expr));  \
        PASS;              \
    } while (0)

#endif /* __UTIL_UNITTEST_H__ */

/**
 * @}
 */
