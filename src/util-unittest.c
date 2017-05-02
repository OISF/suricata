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
 * \defgroup Testing Testing
 *
 * \brief Unit testing support functions.
 *
 * @{
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-time.h"
#include "conf.h"

#include "stream-tcp.h"
#include "stream-tcp-reassemble.h"

#ifdef UNITTESTS

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static UtTest *ut_list;

int unittests_fatal = 0;

/**
 * \brief Allocate UtTest list member
 *
 * \retval ut Pointer to UtTest
 */

static UtTest *UtAllocTest(void)
{
    UtTest *ut = SCMalloc(sizeof(UtTest));
    if (unlikely(ut == NULL))
        return NULL;

    memset(ut, 0, sizeof(UtTest));

    return ut;
}

/**
 * \brief Append test in UtTest list
 *
 * \param list Pointer to the start of the IP packet
 * \param test Pointer to unit test
 *
 * \retval 0 Function always returns zero
 */

static int UtAppendTest(UtTest **list, UtTest *test)
{
    if (*list == NULL) {
        *list = test;
    } else {
        UtTest *tmp = *list;

        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = test;
    }

    return 0;
}

/**
 * \brief Register unit test
 *
 * \param name Unit test name
 * \param TestFn Unit test function
 */

void UtRegisterTest(const char *name, int(*TestFn)(void))
{
    UtTest *ut = UtAllocTest();
    if (ut == NULL)
        return;

    ut->name = name;
    ut->TestFn = TestFn;
    ut->next = NULL;

    /* append */
    UtAppendTest(&ut_list, ut);
}

/**
 * \brief Compile a regex to run a specific unit test
 *
 * \param regex_arg The regular expression
 *
 * \retval 1  Regex compiled
 * \retval -1 Regex error
 */
static int UtRegex (const char *regex_arg)
{
    const char *eb;
    int eo;
    int opts = PCRE_CASELESS;;

    if(regex_arg == NULL)
        return -1;

    parse_regex = pcre_compile(regex_arg, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", regex_arg, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        goto error;
    }

    return 1;

error:
    return -1;
}

#define MAX_SUBSTRINGS 30

/** \brief List all registered unit tests.
 *
 *  \param regex_arg Regular expression to limit listed tests.
 */
void UtListTests(const char *regex_arg)
{
    UtTest *ut;
    int ret = 0, rcomp = 0;
    int ov[MAX_SUBSTRINGS];

    rcomp = UtRegex(regex_arg);

    for (ut = ut_list; ut != NULL; ut = ut->next) {
        if (rcomp == 1)  {
            ret = pcre_exec(parse_regex, parse_regex_study, ut->name,
                strlen(ut->name), 0, 0, ov, MAX_SUBSTRINGS);
            if (ret >= 1) {
                printf("%s\n", ut->name);
            }
        }
        else {
            printf("%s\n", ut->name);
        }
    }
}

/** \brief Run all registered unittests.
 *
 *  \param regex_arg The regular expression
 *
 *  \retval 0 all successful
 *  \retval result number of tests that failed
 */

uint32_t UtRunTests(const char *regex_arg)
{
    UtTest *ut;
    uint32_t good = 0, bad = 0, matchcnt = 0;
    int ret = 0, rcomp = 0;
    int ov[MAX_SUBSTRINGS];

    StreamTcpInitMemuse();
    StreamTcpReassembleInitMemuse();

    rcomp = UtRegex(regex_arg);

    if(rcomp == 1){
        for (ut = ut_list; ut != NULL; ut = ut->next) {
            ret = pcre_exec(parse_regex, parse_regex_study, ut->name, strlen(ut->name), 0, 0, ov, MAX_SUBSTRINGS);
            if( ret >= 1 )  {
                printf("Test %-60.60s : ", ut->name);
                matchcnt++;
                fflush(stdout); /* flush so in case of a segv we see the testname */

                /* reset the time */
                TimeModeSetOffline();
                TimeSetToCurrentTime();

                ret = ut->TestFn();

                if (StreamTcpMemuseCounter() != 0) {
                    printf("STREAM MEMORY IN USE %"PRIu64"\n", StreamTcpMemuseCounter());
                    ret = 0;
                }

                if (StreamTcpReassembleMemuseGlobalCounter() != 0) {
                    printf("STREAM REASSEMBLY MEMORY IN USE %"PRIu64"\n", StreamTcpReassembleMemuseGlobalCounter());
                    ret = 0;
                }

                printf("%s\n", ret ? "pass" : "FAILED");

                if (!ret) {
                    if (unittests_fatal == 1) {
                        fprintf(stderr, "ERROR: unittest failed.\n");
                        exit(EXIT_FAILURE);
                    }
                    bad++;
                } else {
                    good++;
                }
            }
        }
        if(matchcnt > 0){
            printf("==== TEST RESULTS ====\n");
            printf("PASSED: %" PRIu32 "\n", good);
            printf("FAILED: %" PRIu32 "\n", bad);
            printf("======================\n");
        } else {
            SCLogInfo("UtRunTests: regex provided regex_arg: %s did not match any tests",regex_arg);
        }
    } else {
        SCLogInfo("UtRunTests: pcre compilation failed");
    }
    return bad;
}
/**
 * \brief Initialize unit test list
 */

void UtInitialize(void)
{
    ut_list = NULL;
}

/**
 * \brief Cleanup unit test list
 */

void UtCleanup(void)
{

    UtTest *tmp = ut_list, *otmp;

    while (tmp != NULL) {
        otmp = tmp->next;
        SCFree(tmp);
        tmp = otmp;
    }

    ut_list = NULL;
}

void UtRunModeRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_UNITTEST,
                              "unittest",
                              "Unittest mode",
                              NULL);

    return;
}

/*
 * unittests for the unittests code
 */

/** \brief True test
 *
 *  \retval 1 True
 *  \retval 0 False
 */
static int UtSelftestTrue(void)
{
    if (1)return 1;
    else  return 0;
}

/** \brief False test
 *
 *  \retval 1 False
 *  \retval 0 True
 */
static int UtSelftestFalse(void)
{
    if (0)return 0;
    else  return 1;
}

/** \brief Run self tests
 *
 *  \param regex_arg The regular expression
 *
 *  \retval 0 all successful
 */

int UtRunSelftest (const char *regex_arg)
{
    printf("* Running Unittesting subsystem selftests...\n");

    UtInitialize();

    UtRegisterTest("true", UtSelftestTrue);
    UtRegisterTest("false", UtSelftestFalse);

    int ret = UtRunTests(regex_arg);
    if (ret == 0)
        printf("* Done running Unittesting subsystem selftests...\n");
    else
        printf("* ERROR running Unittesting subsystem selftests failed...\n");

    UtCleanup();
    return 0;
}
#endif /* UNITTESTS */

/**
 * @}
 */
