/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * PR (17/01/2010): Single pattern search algorithms:
 * Currently there are 3 algorithms to choose: BasicSearch, Bs2Bm and
 * BoyerMoore (Boyer Moores algorithm). The first one doesn't need a context.
 * But for Bs2Bm and BoyerMoore, you'll need to build some arrays.
 *
 * !! If you are going to use the same pattern multiple times,
 * please, try to store the context some where. For Bs2Bm, the
 * context is an array of "badchars". For BoyerMoore you need to store
 * two arrays of shifts. Have a look at the wrappers and unittests
 * for examples of this. If you cant store the context, use the
 * wrappers: Bs2bmSearch, BoyerMooreSearch, and the ones caseless, or BasicSearch
 * That is the most basic.
 *
 * Use the stats and util-clock.h to determine which one fit better for you
 * Boyer Moore should be used for patterns greater than 1 of length
 * In the range of 2 - 6, if the text length is greater than 1000 you could
 * use boyer moore, otherwise, basic search. If the pattern is greater
 * than 6 and the textlen is greater than 500, use boyer moore.
 * This is an aproximation, but use the stats and util-clock to determine which one
 * fit better for your case.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-unittest.h"

#include "util-spm.h"
#include "util-spm-bs.h"
#include "util-spm-bs2bm.h"
#include "util-spm-bm.h"
#include "util-clock.h"


/**
 * Wrappers for building context and searching (Bs2Bm and boyermoore)
 * Use them if you cant store the context
 *
 */

/**
 * \brief Search a pattern in the text using the Bs2Bm algorithm (build a bad characters array)
 *
 * \param text Text to search in
 * \param textlen length of the text
 * \param needle pattern to search for
 * \param needlelen length of the pattern
 */
uint8_t *Bs2bmSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen)
{
    uint8_t badchars[ALPHABET_SIZE];
    Bs2BmBadchars(needle, needlelen, badchars);

    return Bs2Bm(text, textlen, needle, needlelen, badchars);
}

/**
 * \brief Search a pattern in the text using the Bs2Bm nocase algorithm (build a bad characters array)
 *
 * \param text Text to search in
 * \param textlen length of the text
 * \param needle pattern to search for
 * \param needlelen length of the pattern
 */
uint8_t *Bs2bmNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen)
{
    uint8_t badchars[ALPHABET_SIZE];
    Bs2BmBadchars(needle, needlelen, badchars);

    return Bs2BmNocase(text, textlen, needle, needlelen, badchars);
}

/**
 * \brief Search a pattern in the text using Boyer Moore algorithm
 *        (build a bad character shifts array and good prefixes shift array)
 *
 * \param text Text to search in
 * \param textlen length of the text
 * \param needle pattern to search for
 * \param needlelen length of the pattern
 */
uint8_t *BoyerMooreSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen)
{
    BmCtx *bm_ctx = BoyerMooreCtxInit(needle, needlelen);

    uint8_t *ret = BoyerMoore(needle, needlelen, text, textlen, bm_ctx);
    BoyerMooreCtxDeInit(bm_ctx);

    return ret;
}

/**
 * \brief Search a pattern in the text using Boyer Moore nocase algorithm
 *        (build a bad character shifts array and good prefixes shift array)
 *
 * \param text Text to search in
 * \param textlen length of the text
 * \param needle pattern to search for
 * \param needlelen length of the pattern
 */
uint8_t *BoyerMooreNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen)
{
    BmCtx *bm_ctx = BoyerMooreNocaseCtxInit(needle, needlelen);

    uint8_t *ret = BoyerMooreNocase(needle, needlelen, text, textlen, bm_ctx);
    BoyerMooreCtxDeInit(bm_ctx);

    return ret;
}


#ifdef UNITTESTS

/** Comment out this if you want stats
 *  #define ENABLE_SEARCH_STATS 1
 */

/* Number of times to repeat the search (for stats) */
#define STATS_TIMES 1000000

/**
 * \brief Unittest helper function wrappers for the search algorithms
 * \param text pointer to the buffer to search in
 * \param needle pointer to the pattern to search for
 * \param times If you are testing performance, se the numebr of times
 *              that you want to repeat the search
 */
uint8_t *BasicSearchWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1)
        CLOCK_START;

    for (i = 0; i < times; i++) {
        ret = BasicSearch(text, textlen, needle, needlelen);
    }

    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *BasicSearchNocaseWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = BasicSearchNocase(text, textlen, needle, needlelen);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *Bs2bmWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t badchars[ALPHABET_SIZE];
    Bs2BmBadchars(needle, needlelen, badchars);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = Bs2Bm(text, textlen, needle, needlelen, badchars);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *Bs2bmNocaseWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t badchars[ALPHABET_SIZE];
    Bs2BmBadchars(needle, needlelen, badchars);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = Bs2BmNocase(text, textlen, needle, needlelen, badchars);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *BoyerMooreWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    BmCtx *bm_ctx = BoyerMooreCtxInit(needle, needlelen);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = BoyerMoore(needle, needlelen, text, textlen, bm_ctx);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    BoyerMooreCtxDeInit(bm_ctx);
    return ret;
}

uint8_t *BoyerMooreNocaseWrapper(uint8_t *text, uint8_t *in_needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)in_needle);

    /* Make a copy of in_needle to be able to convert it to lowercase. */
    uint8_t *needle = SCMalloc(needlelen);
    if (needle == NULL)
        return NULL;
    memcpy(needle, in_needle, needlelen);

    BmCtx *bm_ctx = BoyerMooreNocaseCtxInit(needle, needlelen);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = BoyerMooreNocase(needle, needlelen, text, textlen, bm_ctx);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    BoyerMooreCtxDeInit(bm_ctx);
    free(needle);
    return ret;

}

/**
 * \brief Unittest helper function wrappers for the search algorithms
 * \param text pointer to the buffer to search in
 * \param needle pointer to the pattern to search for
 * \param times If you are testing performance, se the numebr of times
 *              that you want to repeat the search
 */
uint8_t *BasicSearchCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        /* This wrapper is a fake, no context needed! */
        ret = BasicSearch(text, textlen, needle, needlelen);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *BasicSearchNocaseCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        /* This wrapper is a fake, no context needed! */
        ret = BasicSearchNocase(text, textlen, needle, needlelen);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *Bs2bmCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t badchars[ALPHABET_SIZE];

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        /* Stats including context building */
        Bs2BmBadchars(needle, needlelen, badchars);
        ret = Bs2Bm(text, textlen, needle, needlelen, badchars);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *Bs2bmNocaseCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t badchars[ALPHABET_SIZE];

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        /* Stats including context building */
        Bs2BmBadchars(needle, needlelen, badchars);
        ret = Bs2BmNocase(text, textlen, needle, needlelen, badchars);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *BoyerMooreCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    BmCtx *bm_ctx = BoyerMooreCtxInit(needle, needlelen);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        /* Stats including context building */
        ret = BoyerMoore(needle, needlelen, text, textlen, bm_ctx);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    BoyerMooreCtxDeInit(bm_ctx);

    return ret;
}

uint8_t *RawCtxWrapper(uint8_t *text, uint8_t *needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)needle);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = SpmSearch(text, textlen, needle, needlelen);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    return ret;
}

uint8_t *BoyerMooreNocaseCtxWrapper(uint8_t *text, uint8_t *in_needle, int times)
{
    uint32_t textlen = strlen((char *)text);
    uint16_t needlelen = strlen((char *)in_needle);

    /* Make a copy of in_needle to be able to convert it to lowercase. */
    uint8_t *needle = SCMalloc(needlelen);
    if (needle == NULL)
        return NULL;
    memcpy(needle, in_needle, needlelen);

    BmCtx *bm_ctx = BoyerMooreNocaseCtxInit(needle, needlelen);

    uint8_t *ret = NULL;
    int i = 0;

    CLOCK_INIT;
    if (times > 1) CLOCK_START;
    for (i = 0; i < times; i++) {
        ret = BoyerMooreNocase(needle, needlelen, text, textlen, bm_ctx);
    }
    if (times > 1) { CLOCK_END; CLOCK_PRINT_SEC; };
    BoyerMooreCtxDeInit(bm_ctx);
    free(needle);
    return ret;

}

/**
 * \test Generic test for BasicSearch matching
 */
int UtilSpmBasicSearchTest01()
{
    uint8_t *needle = (uint8_t *)"oPqRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BasicSearchWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test Generic test for BasicSearch nocase matching
 */
int UtilSpmBasicSearchNocaseTest01()
{
    uint8_t *needle = (uint8_t *)"OpQrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BasicSearchNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test Generic test for Bs2Bm matching
 */
int UtilSpmBs2bmSearchTest01()
{
    uint8_t *needle = (uint8_t *)"oPqRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = Bs2bmWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test Generic test for Bs2Bm no case matching
 */
int UtilSpmBs2bmSearchNocaseTest01()
{
    uint8_t *needle = (uint8_t *)"OpQrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = Bs2bmNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test Generic test for boyer moore matching
 */
int UtilSpmBoyerMooreSearchTest01()
{
    uint8_t *needle = (uint8_t *)"oPqRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BoyerMooreWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test Generic test for boyer moore nocase matching
 */
int UtilSpmBoyerMooreSearchNocaseTest01()
{
    uint8_t *needle = (uint8_t *)"OpQrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BoyerMooreNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/**
 * \test issue 130 (@redmine) check to ensure that the
 *       problem is not the algorithm implementation
 */
int UtilSpmBoyerMooreSearchNocaseTestIssue130()
{
    uint8_t *needle = (uint8_t *)"WWW-Authenticate: ";
    uint8_t *text = (uint8_t *)"Date: Mon, 23 Feb 2009 13:31:49 GMT"
                "Server: Apache\r\n"
                "Www-authenticate: Basic realm=\"Authentification user password\"\r\n"
                "Vary: accept-language,accept-charset\r\n"
                "Accept-ranges: bytes\r\n"
                "Connection: close\r\n"
                "Content-type: text/html; charset=iso-8859-1\r\n"
                "Content-language: fr\r\n"
                "Expires: Mon, 23 Feb 2009 13:31:49 GMT\r\n\r\n";
    uint8_t *found = BoyerMooreNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 1;
    else
        return 0;
}

/* Generic tests that should not match */
int UtilSpmBasicSearchTest02()
{
    uint8_t *needle = (uint8_t *)"oPQRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BasicSearchWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

int UtilSpmBasicSearchNocaseTest02()
{
    uint8_t *needle = (uint8_t *)"OpZrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BasicSearchNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

int UtilSpmBs2bmSearchTest02()
{
    uint8_t *needle = (uint8_t *)"oPQRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = Bs2bmWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

int UtilSpmBs2bmSearchNocaseTest02()
{
    uint8_t *needle = (uint8_t *)"OpZrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = Bs2bmNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

int UtilSpmBoyerMooreSearchTest02()
{
    uint8_t *needle = (uint8_t *)"oPQRsT";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BoyerMooreWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

int UtilSpmBoyerMooreSearchNocaseTest02()
{
    uint8_t *needle = (uint8_t *)"OpZrSt";
    uint8_t *text = (uint8_t *)"aBcDeFgHiJkLmNoPqRsTuVwXyZ";
    uint8_t *found = BoyerMooreNocaseWrapper(text, needle, 1);
    //printf("found: %s\n", found);
    if (found != NULL)
        return 0;
    else
        return 1;
}

/**
 * \test Check that all the algorithms work at any offset and any pattern length
 */
int UtilSpmSearchOffsetsTest01()
{
    char *text[26][27];
    text[0][0]="azzzzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][1]="zazzzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][2]="zzazzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][3]="zzzazzzzzzzzzzzzzzzzzzzzzzz";
    text[0][4]="zzzzazzzzzzzzzzzzzzzzzzzzzz";
    text[0][5]="zzzzzazzzzzzzzzzzzzzzzzzzzz";
    text[0][6]="zzzzzzazzzzzzzzzzzzzzzzzzzz";
    text[0][7]="zzzzzzzazzzzzzzzzzzzzzzzzzz";
    text[0][8]="zzzzzzzzazzzzzzzzzzzzzzzzzz";
    text[0][9]="zzzzzzzzzazzzzzzzzzzzzzzzzz";
    text[0][10]="zzzzzzzzzzazzzzzzzzzzzzzzzz";
    text[0][11]="zzzzzzzzzzzazzzzzzzzzzzzzzz";
    text[0][12]="zzzzzzzzzzzzazzzzzzzzzzzzzz";
    text[0][13]="zzzzzzzzzzzzzazzzzzzzzzzzzz";
    text[0][14]="zzzzzzzzzzzzzzazzzzzzzzzzzz";
    text[0][15]="zzzzzzzzzzzzzzzazzzzzzzzzzz";
    text[0][16]="zzzzzzzzzzzzzzzzazzzzzzzzzz";
    text[0][17]="zzzzzzzzzzzzzzzzzazzzzzzzzz";
    text[0][18]="zzzzzzzzzzzzzzzzzzazzzzzzzz";
    text[0][19]="zzzzzzzzzzzzzzzzzzzazzzzzzz";
    text[0][20]="zzzzzzzzzzzzzzzzzzzzazzzzzz";
    text[0][21]="zzzzzzzzzzzzzzzzzzzzzazzzzz";
    text[0][22]="zzzzzzzzzzzzzzzzzzzzzzazzzz";
    text[0][23]="zzzzzzzzzzzzzzzzzzzzzzzazzz";
    text[0][24]="zzzzzzzzzzzzzzzzzzzzzzzzazz";
    text[0][25]="zzzzzzzzzzzzzzzzzzzzzzzzzaz";
    text[0][26]="zzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1][0]="aBzzzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][1]="zaBzzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][2]="zzaBzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][3]="zzzaBzzzzzzzzzzzzzzzzzzzzzz";
    text[1][4]="zzzzaBzzzzzzzzzzzzzzzzzzzzz";
    text[1][5]="zzzzzaBzzzzzzzzzzzzzzzzzzzz";
    text[1][6]="zzzzzzaBzzzzzzzzzzzzzzzzzzz";
    text[1][7]="zzzzzzzaBzzzzzzzzzzzzzzzzzz";
    text[1][8]="zzzzzzzzaBzzzzzzzzzzzzzzzzz";
    text[1][9]="zzzzzzzzzaBzzzzzzzzzzzzzzzz";
    text[1][10]="zzzzzzzzzzaBzzzzzzzzzzzzzzz";
    text[1][11]="zzzzzzzzzzzaBzzzzzzzzzzzzzz";
    text[1][12]="zzzzzzzzzzzzaBzzzzzzzzzzzzz";
    text[1][13]="zzzzzzzzzzzzzaBzzzzzzzzzzzz";
    text[1][14]="zzzzzzzzzzzzzzaBzzzzzzzzzzz";
    text[1][15]="zzzzzzzzzzzzzzzaBzzzzzzzzzz";
    text[1][16]="zzzzzzzzzzzzzzzzaBzzzzzzzzz";
    text[1][17]="zzzzzzzzzzzzzzzzzaBzzzzzzzz";
    text[1][18]="zzzzzzzzzzzzzzzzzzaBzzzzzzz";
    text[1][19]="zzzzzzzzzzzzzzzzzzzaBzzzzzz";
    text[1][20]="zzzzzzzzzzzzzzzzzzzzaBzzzzz";
    text[1][21]="zzzzzzzzzzzzzzzzzzzzzaBzzzz";
    text[1][22]="zzzzzzzzzzzzzzzzzzzzzzaBzzz";
    text[1][23]="zzzzzzzzzzzzzzzzzzzzzzzaBzz";
    text[1][24]="zzzzzzzzzzzzzzzzzzzzzzzzaBz";
    text[1][25]="zzzzzzzzzzzzzzzzzzzzzzzzzaB";
    text[2][0]="aBczzzzzzzzzzzzzzzzzzzzzzzz";
    text[2][1]="zaBczzzzzzzzzzzzzzzzzzzzzzz";
    text[2][2]="zzaBczzzzzzzzzzzzzzzzzzzzzz";
    text[2][3]="zzzaBczzzzzzzzzzzzzzzzzzzzz";
    text[2][4]="zzzzaBczzzzzzzzzzzzzzzzzzzz";
    text[2][5]="zzzzzaBczzzzzzzzzzzzzzzzzzz";
    text[2][6]="zzzzzzaBczzzzzzzzzzzzzzzzzz";
    text[2][7]="zzzzzzzaBczzzzzzzzzzzzzzzzz";
    text[2][8]="zzzzzzzzaBczzzzzzzzzzzzzzzz";
    text[2][9]="zzzzzzzzzaBczzzzzzzzzzzzzzz";
    text[2][10]="zzzzzzzzzzaBczzzzzzzzzzzzzz";
    text[2][11]="zzzzzzzzzzzaBczzzzzzzzzzzzz";
    text[2][12]="zzzzzzzzzzzzaBczzzzzzzzzzzz";
    text[2][13]="zzzzzzzzzzzzzaBczzzzzzzzzzz";
    text[2][14]="zzzzzzzzzzzzzzaBczzzzzzzzzz";
    text[2][15]="zzzzzzzzzzzzzzzaBczzzzzzzzz";
    text[2][16]="zzzzzzzzzzzzzzzzaBczzzzzzzz";
    text[2][17]="zzzzzzzzzzzzzzzzzaBczzzzzzz";
    text[2][18]="zzzzzzzzzzzzzzzzzzaBczzzzzz";
    text[2][19]="zzzzzzzzzzzzzzzzzzzaBczzzzz";
    text[2][20]="zzzzzzzzzzzzzzzzzzzzaBczzzz";
    text[2][21]="zzzzzzzzzzzzzzzzzzzzzaBczzz";
    text[2][22]="zzzzzzzzzzzzzzzzzzzzzzaBczz";
    text[2][23]="zzzzzzzzzzzzzzzzzzzzzzzaBcz";
    text[2][24]="zzzzzzzzzzzzzzzzzzzzzzzzaBc";
    text[3][0]="aBcDzzzzzzzzzzzzzzzzzzzzzzz";
    text[3][1]="zaBcDzzzzzzzzzzzzzzzzzzzzzz";
    text[3][2]="zzaBcDzzzzzzzzzzzzzzzzzzzzz";
    text[3][3]="zzzaBcDzzzzzzzzzzzzzzzzzzzz";
    text[3][4]="zzzzaBcDzzzzzzzzzzzzzzzzzzz";
    text[3][5]="zzzzzaBcDzzzzzzzzzzzzzzzzzz";
    text[3][6]="zzzzzzaBcDzzzzzzzzzzzzzzzzz";
    text[3][7]="zzzzzzzaBcDzzzzzzzzzzzzzzzz";
    text[3][8]="zzzzzzzzaBcDzzzzzzzzzzzzzzz";
    text[3][9]="zzzzzzzzzaBcDzzzzzzzzzzzzzz";
    text[3][10]="zzzzzzzzzzaBcDzzzzzzzzzzzzz";
    text[3][11]="zzzzzzzzzzzaBcDzzzzzzzzzzzz";
    text[3][12]="zzzzzzzzzzzzaBcDzzzzzzzzzzz";
    text[3][13]="zzzzzzzzzzzzzaBcDzzzzzzzzzz";
    text[3][14]="zzzzzzzzzzzzzzaBcDzzzzzzzzz";
    text[3][15]="zzzzzzzzzzzzzzzaBcDzzzzzzzz";
    text[3][16]="zzzzzzzzzzzzzzzzaBcDzzzzzzz";
    text[3][17]="zzzzzzzzzzzzzzzzzaBcDzzzzzz";
    text[3][18]="zzzzzzzzzzzzzzzzzzaBcDzzzzz";
    text[3][19]="zzzzzzzzzzzzzzzzzzzaBcDzzzz";
    text[3][20]="zzzzzzzzzzzzzzzzzzzzaBcDzzz";
    text[3][21]="zzzzzzzzzzzzzzzzzzzzzaBcDzz";
    text[3][22]="zzzzzzzzzzzzzzzzzzzzzzaBcDz";
    text[3][23]="zzzzzzzzzzzzzzzzzzzzzzzaBcD";
    text[4][0]="aBcDezzzzzzzzzzzzzzzzzzzzzz";
    text[4][1]="zaBcDezzzzzzzzzzzzzzzzzzzzz";
    text[4][2]="zzaBcDezzzzzzzzzzzzzzzzzzzz";
    text[4][3]="zzzaBcDezzzzzzzzzzzzzzzzzzz";
    text[4][4]="zzzzaBcDezzzzzzzzzzzzzzzzzz";
    text[4][5]="zzzzzaBcDezzzzzzzzzzzzzzzzz";
    text[4][6]="zzzzzzaBcDezzzzzzzzzzzzzzzz";
    text[4][7]="zzzzzzzaBcDezzzzzzzzzzzzzzz";
    text[4][8]="zzzzzzzzaBcDezzzzzzzzzzzzzz";
    text[4][9]="zzzzzzzzzaBcDezzzzzzzzzzzzz";
    text[4][10]="zzzzzzzzzzaBcDezzzzzzzzzzzz";
    text[4][11]="zzzzzzzzzzzaBcDezzzzzzzzzzz";
    text[4][12]="zzzzzzzzzzzzaBcDezzzzzzzzzz";
    text[4][13]="zzzzzzzzzzzzzaBcDezzzzzzzzz";
    text[4][14]="zzzzzzzzzzzzzzaBcDezzzzzzzz";
    text[4][15]="zzzzzzzzzzzzzzzaBcDezzzzzzz";
    text[4][16]="zzzzzzzzzzzzzzzzaBcDezzzzzz";
    text[4][17]="zzzzzzzzzzzzzzzzzaBcDezzzzz";
    text[4][18]="zzzzzzzzzzzzzzzzzzaBcDezzzz";
    text[4][19]="zzzzzzzzzzzzzzzzzzzaBcDezzz";
    text[4][20]="zzzzzzzzzzzzzzzzzzzzaBcDezz";
    text[4][21]="zzzzzzzzzzzzzzzzzzzzzaBcDez";
    text[4][22]="zzzzzzzzzzzzzzzzzzzzzzaBcDe";
    text[5][0]="aBcDeFzzzzzzzzzzzzzzzzzzzzz";
    text[5][1]="zaBcDeFzzzzzzzzzzzzzzzzzzzz";
    text[5][2]="zzaBcDeFzzzzzzzzzzzzzzzzzzz";
    text[5][3]="zzzaBcDeFzzzzzzzzzzzzzzzzzz";
    text[5][4]="zzzzaBcDeFzzzzzzzzzzzzzzzzz";
    text[5][5]="zzzzzaBcDeFzzzzzzzzzzzzzzzz";
    text[5][6]="zzzzzzaBcDeFzzzzzzzzzzzzzzz";
    text[5][7]="zzzzzzzaBcDeFzzzzzzzzzzzzzz";
    text[5][8]="zzzzzzzzaBcDeFzzzzzzzzzzzzz";
    text[5][9]="zzzzzzzzzaBcDeFzzzzzzzzzzzz";
    text[5][10]="zzzzzzzzzzaBcDeFzzzzzzzzzzz";
    text[5][11]="zzzzzzzzzzzaBcDeFzzzzzzzzzz";
    text[5][12]="zzzzzzzzzzzzaBcDeFzzzzzzzzz";
    text[5][13]="zzzzzzzzzzzzzaBcDeFzzzzzzzz";
    text[5][14]="zzzzzzzzzzzzzzaBcDeFzzzzzzz";
    text[5][15]="zzzzzzzzzzzzzzzaBcDeFzzzzzz";
    text[5][16]="zzzzzzzzzzzzzzzzaBcDeFzzzzz";
    text[5][17]="zzzzzzzzzzzzzzzzzaBcDeFzzzz";
    text[5][18]="zzzzzzzzzzzzzzzzzzaBcDeFzzz";
    text[5][19]="zzzzzzzzzzzzzzzzzzzaBcDeFzz";
    text[5][20]="zzzzzzzzzzzzzzzzzzzzaBcDeFz";
    text[5][21]="zzzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6][0]="aBcDeFgzzzzzzzzzzzzzzzzzzzz";
    text[6][1]="zaBcDeFgzzzzzzzzzzzzzzzzzzz";
    text[6][2]="zzaBcDeFgzzzzzzzzzzzzzzzzzz";
    text[6][3]="zzzaBcDeFgzzzzzzzzzzzzzzzzz";
    text[6][4]="zzzzaBcDeFgzzzzzzzzzzzzzzzz";
    text[6][5]="zzzzzaBcDeFgzzzzzzzzzzzzzzz";
    text[6][6]="zzzzzzaBcDeFgzzzzzzzzzzzzzz";
    text[6][7]="zzzzzzzaBcDeFgzzzzzzzzzzzzz";
    text[6][8]="zzzzzzzzaBcDeFgzzzzzzzzzzzz";
    text[6][9]="zzzzzzzzzaBcDeFgzzzzzzzzzzz";
    text[6][10]="zzzzzzzzzzaBcDeFgzzzzzzzzzz";
    text[6][11]="zzzzzzzzzzzaBcDeFgzzzzzzzzz";
    text[6][12]="zzzzzzzzzzzzaBcDeFgzzzzzzzz";
    text[6][13]="zzzzzzzzzzzzzaBcDeFgzzzzzzz";
    text[6][14]="zzzzzzzzzzzzzzaBcDeFgzzzzzz";
    text[6][15]="zzzzzzzzzzzzzzzaBcDeFgzzzzz";
    text[6][16]="zzzzzzzzzzzzzzzzaBcDeFgzzzz";
    text[6][17]="zzzzzzzzzzzzzzzzzaBcDeFgzzz";
    text[6][18]="zzzzzzzzzzzzzzzzzzaBcDeFgzz";
    text[6][19]="zzzzzzzzzzzzzzzzzzzaBcDeFgz";
    text[6][20]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7][0]="aBcDeFgHzzzzzzzzzzzzzzzzzzz";
    text[7][1]="zaBcDeFgHzzzzzzzzzzzzzzzzzz";
    text[7][2]="zzaBcDeFgHzzzzzzzzzzzzzzzzz";
    text[7][3]="zzzaBcDeFgHzzzzzzzzzzzzzzzz";
    text[7][4]="zzzzaBcDeFgHzzzzzzzzzzzzzzz";
    text[7][5]="zzzzzaBcDeFgHzzzzzzzzzzzzzz";
    text[7][6]="zzzzzzaBcDeFgHzzzzzzzzzzzzz";
    text[7][7]="zzzzzzzaBcDeFgHzzzzzzzzzzzz";
    text[7][8]="zzzzzzzzaBcDeFgHzzzzzzzzzzz";
    text[7][9]="zzzzzzzzzaBcDeFgHzzzzzzzzzz";
    text[7][10]="zzzzzzzzzzaBcDeFgHzzzzzzzzz";
    text[7][11]="zzzzzzzzzzzaBcDeFgHzzzzzzzz";
    text[7][12]="zzzzzzzzzzzzaBcDeFgHzzzzzzz";
    text[7][13]="zzzzzzzzzzzzzaBcDeFgHzzzzzz";
    text[7][14]="zzzzzzzzzzzzzzaBcDeFgHzzzzz";
    text[7][15]="zzzzzzzzzzzzzzzaBcDeFgHzzzz";
    text[7][16]="zzzzzzzzzzzzzzzzaBcDeFgHzzz";
    text[7][17]="zzzzzzzzzzzzzzzzzaBcDeFgHzz";
    text[7][18]="zzzzzzzzzzzzzzzzzzaBcDeFgHz";
    text[7][19]="zzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8][0]="aBcDeFgHizzzzzzzzzzzzzzzzzz";
    text[8][1]="zaBcDeFgHizzzzzzzzzzzzzzzzz";
    text[8][2]="zzaBcDeFgHizzzzzzzzzzzzzzzz";
    text[8][3]="zzzaBcDeFgHizzzzzzzzzzzzzzz";
    text[8][4]="zzzzaBcDeFgHizzzzzzzzzzzzzz";
    text[8][5]="zzzzzaBcDeFgHizzzzzzzzzzzzz";
    text[8][6]="zzzzzzaBcDeFgHizzzzzzzzzzzz";
    text[8][7]="zzzzzzzaBcDeFgHizzzzzzzzzzz";
    text[8][8]="zzzzzzzzaBcDeFgHizzzzzzzzzz";
    text[8][9]="zzzzzzzzzaBcDeFgHizzzzzzzzz";
    text[8][10]="zzzzzzzzzzaBcDeFgHizzzzzzzz";
    text[8][11]="zzzzzzzzzzzaBcDeFgHizzzzzzz";
    text[8][12]="zzzzzzzzzzzzaBcDeFgHizzzzzz";
    text[8][13]="zzzzzzzzzzzzzaBcDeFgHizzzzz";
    text[8][14]="zzzzzzzzzzzzzzaBcDeFgHizzzz";
    text[8][15]="zzzzzzzzzzzzzzzaBcDeFgHizzz";
    text[8][16]="zzzzzzzzzzzzzzzzaBcDeFgHizz";
    text[8][17]="zzzzzzzzzzzzzzzzzaBcDeFgHiz";
    text[8][18]="zzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9][0]="aBcDeFgHiJzzzzzzzzzzzzzzzzz";
    text[9][1]="zaBcDeFgHiJzzzzzzzzzzzzzzzz";
    text[9][2]="zzaBcDeFgHiJzzzzzzzzzzzzzzz";
    text[9][3]="zzzaBcDeFgHiJzzzzzzzzzzzzzz";
    text[9][4]="zzzzaBcDeFgHiJzzzzzzzzzzzzz";
    text[9][5]="zzzzzaBcDeFgHiJzzzzzzzzzzzz";
    text[9][6]="zzzzzzaBcDeFgHiJzzzzzzzzzzz";
    text[9][7]="zzzzzzzaBcDeFgHiJzzzzzzzzzz";
    text[9][8]="zzzzzzzzaBcDeFgHiJzzzzzzzzz";
    text[9][9]="zzzzzzzzzaBcDeFgHiJzzzzzzzz";
    text[9][10]="zzzzzzzzzzaBcDeFgHiJzzzzzzz";
    text[9][11]="zzzzzzzzzzzaBcDeFgHiJzzzzzz";
    text[9][12]="zzzzzzzzzzzzaBcDeFgHiJzzzzz";
    text[9][13]="zzzzzzzzzzzzzaBcDeFgHiJzzzz";
    text[9][14]="zzzzzzzzzzzzzzaBcDeFgHiJzzz";
    text[9][15]="zzzzzzzzzzzzzzzaBcDeFgHiJzz";
    text[9][16]="zzzzzzzzzzzzzzzzaBcDeFgHiJz";
    text[9][17]="zzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10][0]="aBcDeFgHiJkzzzzzzzzzzzzzzzz";
    text[10][1]="zaBcDeFgHiJkzzzzzzzzzzzzzzz";
    text[10][2]="zzaBcDeFgHiJkzzzzzzzzzzzzzz";
    text[10][3]="zzzaBcDeFgHiJkzzzzzzzzzzzzz";
    text[10][4]="zzzzaBcDeFgHiJkzzzzzzzzzzzz";
    text[10][5]="zzzzzaBcDeFgHiJkzzzzzzzzzzz";
    text[10][6]="zzzzzzaBcDeFgHiJkzzzzzzzzzz";
    text[10][7]="zzzzzzzaBcDeFgHiJkzzzzzzzzz";
    text[10][8]="zzzzzzzzaBcDeFgHiJkzzzzzzzz";
    text[10][9]="zzzzzzzzzaBcDeFgHiJkzzzzzzz";
    text[10][10]="zzzzzzzzzzaBcDeFgHiJkzzzzzz";
    text[10][11]="zzzzzzzzzzzaBcDeFgHiJkzzzzz";
    text[10][12]="zzzzzzzzzzzzaBcDeFgHiJkzzzz";
    text[10][13]="zzzzzzzzzzzzzaBcDeFgHiJkzzz";
    text[10][14]="zzzzzzzzzzzzzzaBcDeFgHiJkzz";
    text[10][15]="zzzzzzzzzzzzzzzaBcDeFgHiJkz";
    text[10][16]="zzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11][0]="aBcDeFgHiJkLzzzzzzzzzzzzzzz";
    text[11][1]="zaBcDeFgHiJkLzzzzzzzzzzzzzz";
    text[11][2]="zzaBcDeFgHiJkLzzzzzzzzzzzzz";
    text[11][3]="zzzaBcDeFgHiJkLzzzzzzzzzzzz";
    text[11][4]="zzzzaBcDeFgHiJkLzzzzzzzzzzz";
    text[11][5]="zzzzzaBcDeFgHiJkLzzzzzzzzzz";
    text[11][6]="zzzzzzaBcDeFgHiJkLzzzzzzzzz";
    text[11][7]="zzzzzzzaBcDeFgHiJkLzzzzzzzz";
    text[11][8]="zzzzzzzzaBcDeFgHiJkLzzzzzzz";
    text[11][9]="zzzzzzzzzaBcDeFgHiJkLzzzzzz";
    text[11][10]="zzzzzzzzzzaBcDeFgHiJkLzzzzz";
    text[11][11]="zzzzzzzzzzzaBcDeFgHiJkLzzzz";
    text[11][12]="zzzzzzzzzzzzaBcDeFgHiJkLzzz";
    text[11][13]="zzzzzzzzzzzzzaBcDeFgHiJkLzz";
    text[11][14]="zzzzzzzzzzzzzzaBcDeFgHiJkLz";
    text[11][15]="zzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12][0]="aBcDeFgHiJkLmzzzzzzzzzzzzzz";
    text[12][1]="zaBcDeFgHiJkLmzzzzzzzzzzzzz";
    text[12][2]="zzaBcDeFgHiJkLmzzzzzzzzzzzz";
    text[12][3]="zzzaBcDeFgHiJkLmzzzzzzzzzzz";
    text[12][4]="zzzzaBcDeFgHiJkLmzzzzzzzzzz";
    text[12][5]="zzzzzaBcDeFgHiJkLmzzzzzzzzz";
    text[12][6]="zzzzzzaBcDeFgHiJkLmzzzzzzzz";
    text[12][7]="zzzzzzzaBcDeFgHiJkLmzzzzzzz";
    text[12][8]="zzzzzzzzaBcDeFgHiJkLmzzzzzz";
    text[12][9]="zzzzzzzzzaBcDeFgHiJkLmzzzzz";
    text[12][10]="zzzzzzzzzzaBcDeFgHiJkLmzzzz";
    text[12][11]="zzzzzzzzzzzaBcDeFgHiJkLmzzz";
    text[12][12]="zzzzzzzzzzzzaBcDeFgHiJkLmzz";
    text[12][13]="zzzzzzzzzzzzzaBcDeFgHiJkLmz";
    text[12][14]="zzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13][0]="aBcDeFgHiJkLmNzzzzzzzzzzzzz";
    text[13][1]="zaBcDeFgHiJkLmNzzzzzzzzzzzz";
    text[13][2]="zzaBcDeFgHiJkLmNzzzzzzzzzzz";
    text[13][3]="zzzaBcDeFgHiJkLmNzzzzzzzzzz";
    text[13][4]="zzzzaBcDeFgHiJkLmNzzzzzzzzz";
    text[13][5]="zzzzzaBcDeFgHiJkLmNzzzzzzzz";
    text[13][6]="zzzzzzaBcDeFgHiJkLmNzzzzzzz";
    text[13][7]="zzzzzzzaBcDeFgHiJkLmNzzzzzz";
    text[13][8]="zzzzzzzzaBcDeFgHiJkLmNzzzzz";
    text[13][9]="zzzzzzzzzaBcDeFgHiJkLmNzzzz";
    text[13][10]="zzzzzzzzzzaBcDeFgHiJkLmNzzz";
    text[13][11]="zzzzzzzzzzzaBcDeFgHiJkLmNzz";
    text[13][12]="zzzzzzzzzzzzaBcDeFgHiJkLmNz";
    text[13][13]="zzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14][0]="aBcDeFgHiJkLmNozzzzzzzzzzzz";
    text[14][1]="zaBcDeFgHiJkLmNozzzzzzzzzzz";
    text[14][2]="zzaBcDeFgHiJkLmNozzzzzzzzzz";
    text[14][3]="zzzaBcDeFgHiJkLmNozzzzzzzzz";
    text[14][4]="zzzzaBcDeFgHiJkLmNozzzzzzzz";
    text[14][5]="zzzzzaBcDeFgHiJkLmNozzzzzzz";
    text[14][6]="zzzzzzaBcDeFgHiJkLmNozzzzzz";
    text[14][7]="zzzzzzzaBcDeFgHiJkLmNozzzzz";
    text[14][8]="zzzzzzzzaBcDeFgHiJkLmNozzzz";
    text[14][9]="zzzzzzzzzaBcDeFgHiJkLmNozzz";
    text[14][10]="zzzzzzzzzzaBcDeFgHiJkLmNozz";
    text[14][11]="zzzzzzzzzzzaBcDeFgHiJkLmNoz";
    text[14][12]="zzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15][0]="aBcDeFgHiJkLmNoPzzzzzzzzzzz";
    text[15][1]="zaBcDeFgHiJkLmNoPzzzzzzzzzz";
    text[15][2]="zzaBcDeFgHiJkLmNoPzzzzzzzzz";
    text[15][3]="zzzaBcDeFgHiJkLmNoPzzzzzzzz";
    text[15][4]="zzzzaBcDeFgHiJkLmNoPzzzzzzz";
    text[15][5]="zzzzzaBcDeFgHiJkLmNoPzzzzzz";
    text[15][6]="zzzzzzaBcDeFgHiJkLmNoPzzzzz";
    text[15][7]="zzzzzzzaBcDeFgHiJkLmNoPzzzz";
    text[15][8]="zzzzzzzzaBcDeFgHiJkLmNoPzzz";
    text[15][9]="zzzzzzzzzaBcDeFgHiJkLmNoPzz";
    text[15][10]="zzzzzzzzzzaBcDeFgHiJkLmNoPz";
    text[15][11]="zzzzzzzzzzzaBcDeFgHiJkLmNoP";
    text[16][0]="aBcDeFgHiJkLmNoPqzzzzzzzzzz";
    text[16][1]="zaBcDeFgHiJkLmNoPqzzzzzzzzz";
    text[16][2]="zzaBcDeFgHiJkLmNoPqzzzzzzzz";
    text[16][3]="zzzaBcDeFgHiJkLmNoPqzzzzzzz";
    text[16][4]="zzzzaBcDeFgHiJkLmNoPqzzzzzz";
    text[16][5]="zzzzzaBcDeFgHiJkLmNoPqzzzzz";
    text[16][6]="zzzzzzaBcDeFgHiJkLmNoPqzzzz";
    text[16][7]="zzzzzzzaBcDeFgHiJkLmNoPqzzz";
    text[16][8]="zzzzzzzzaBcDeFgHiJkLmNoPqzz";
    text[16][9]="zzzzzzzzzaBcDeFgHiJkLmNoPqz";
    text[16][10]="zzzzzzzzzzaBcDeFgHiJkLmNoPq";
    text[17][0]="aBcDeFgHiJkLmNoPqRzzzzzzzzz";
    text[17][1]="zaBcDeFgHiJkLmNoPqRzzzzzzzz";
    text[17][2]="zzaBcDeFgHiJkLmNoPqRzzzzzzz";
    text[17][3]="zzzaBcDeFgHiJkLmNoPqRzzzzzz";
    text[17][4]="zzzzaBcDeFgHiJkLmNoPqRzzzzz";
    text[17][5]="zzzzzaBcDeFgHiJkLmNoPqRzzzz";
    text[17][6]="zzzzzzaBcDeFgHiJkLmNoPqRzzz";
    text[17][7]="zzzzzzzaBcDeFgHiJkLmNoPqRzz";
    text[17][8]="zzzzzzzzaBcDeFgHiJkLmNoPqRz";
    text[17][9]="zzzzzzzzzaBcDeFgHiJkLmNoPqR";
    text[18][0]="aBcDeFgHiJkLmNoPqRszzzzzzzz";
    text[18][1]="zaBcDeFgHiJkLmNoPqRszzzzzzz";
    text[18][2]="zzaBcDeFgHiJkLmNoPqRszzzzzz";
    text[18][3]="zzzaBcDeFgHiJkLmNoPqRszzzzz";
    text[18][4]="zzzzaBcDeFgHiJkLmNoPqRszzzz";
    text[18][5]="zzzzzaBcDeFgHiJkLmNoPqRszzz";
    text[18][6]="zzzzzzaBcDeFgHiJkLmNoPqRszz";
    text[18][7]="zzzzzzzaBcDeFgHiJkLmNoPqRsz";
    text[18][8]="zzzzzzzzaBcDeFgHiJkLmNoPqRs";
    text[19][0]="aBcDeFgHiJkLmNoPqRsTzzzzzzz";
    text[19][1]="zaBcDeFgHiJkLmNoPqRsTzzzzzz";
    text[19][2]="zzaBcDeFgHiJkLmNoPqRsTzzzzz";
    text[19][3]="zzzaBcDeFgHiJkLmNoPqRsTzzzz";
    text[19][4]="zzzzaBcDeFgHiJkLmNoPqRsTzzz";
    text[19][5]="zzzzzaBcDeFgHiJkLmNoPqRsTzz";
    text[19][6]="zzzzzzaBcDeFgHiJkLmNoPqRsTz";
    text[19][7]="zzzzzzzaBcDeFgHiJkLmNoPqRsT";
    text[20][0]="aBcDeFgHiJkLmNoPqRsTuzzzzzz";
    text[20][1]="zaBcDeFgHiJkLmNoPqRsTuzzzzz";
    text[20][2]="zzaBcDeFgHiJkLmNoPqRsTuzzzz";
    text[20][3]="zzzaBcDeFgHiJkLmNoPqRsTuzzz";
    text[20][4]="zzzzaBcDeFgHiJkLmNoPqRsTuzz";
    text[20][5]="zzzzzaBcDeFgHiJkLmNoPqRsTuz";
    text[20][6]="zzzzzzaBcDeFgHiJkLmNoPqRsTu";
    text[21][0]="aBcDeFgHiJkLmNoPqRsTuVzzzzz";
    text[21][1]="zaBcDeFgHiJkLmNoPqRsTuVzzzz";
    text[21][2]="zzaBcDeFgHiJkLmNoPqRsTuVzzz";
    text[21][3]="zzzaBcDeFgHiJkLmNoPqRsTuVzz";
    text[21][4]="zzzzaBcDeFgHiJkLmNoPqRsTuVz";
    text[21][5]="zzzzzaBcDeFgHiJkLmNoPqRsTuV";
    text[22][0]="aBcDeFgHiJkLmNoPqRsTuVwzzzz";
    text[22][1]="zaBcDeFgHiJkLmNoPqRsTuVwzzz";
    text[22][2]="zzaBcDeFgHiJkLmNoPqRsTuVwzz";
    text[22][3]="zzzaBcDeFgHiJkLmNoPqRsTuVwz";
    text[22][4]="zzzzaBcDeFgHiJkLmNoPqRsTuVw";
    text[23][0]="aBcDeFgHiJkLmNoPqRsTuVwXzzz";
    text[23][1]="zaBcDeFgHiJkLmNoPqRsTuVwXzz";
    text[23][2]="zzaBcDeFgHiJkLmNoPqRsTuVwXz";
    text[23][3]="zzzaBcDeFgHiJkLmNoPqRsTuVwX";
    text[24][0]="aBcDeFgHiJkLmNoPqRsTuVwXyzz";
    text[24][1]="zaBcDeFgHiJkLmNoPqRsTuVwXyz";
    text[24][2]="zzaBcDeFgHiJkLmNoPqRsTuVwXy";
    text[25][0]="aBcDeFgHiJkLmNoPqRsTuVwXyZz";
    text[25][1]="zaBcDeFgHiJkLmNoPqRsTuVwXyZ";

    char *needle[26];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";
    needle[16]="aBcDeFgHiJkLmNoPq";
    needle[17]="aBcDeFgHiJkLmNoPqR";
    needle[18]="aBcDeFgHiJkLmNoPqRs";
    needle[19]="aBcDeFgHiJkLmNoPqRsT";
    needle[20]="aBcDeFgHiJkLmNoPqRsTu";
    needle[21]="aBcDeFgHiJkLmNoPqRsTuV";
    needle[22]="aBcDeFgHiJkLmNoPqRsTuVw";
    needle[23]="aBcDeFgHiJkLmNoPqRsTuVwX";
    needle[24]="aBcDeFgHiJkLmNoPqRsTuVwXy";
    needle[25]="aBcDeFgHiJkLmNoPqRsTuVwXyZ";

    int i, j;
    uint8_t *found = NULL;
    for (i = 0; i < 26; i++) {
        for (j = 0; j <= (26 - i); j++) {
            found = BasicSearchWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error1 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
            found = Bs2bmWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error2 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
            found = BoyerMooreWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error3 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
        }
    }
    return 1;
}

/**
 * \test Check that all the algorithms (no case) work at any offset and any pattern length
 */
int UtilSpmSearchOffsetsNocaseTest01()
{
    char *text[26][27];
    text[0][0]="azzzzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][1]="zazzzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][2]="zzazzzzzzzzzzzzzzzzzzzzzzzz";
    text[0][3]="zzzazzzzzzzzzzzzzzzzzzzzzzz";
    text[0][4]="zzzzazzzzzzzzzzzzzzzzzzzzzz";
    text[0][5]="zzzzzazzzzzzzzzzzzzzzzzzzzz";
    text[0][6]="zzzzzzazzzzzzzzzzzzzzzzzzzz";
    text[0][7]="zzzzzzzazzzzzzzzzzzzzzzzzzz";
    text[0][8]="zzzzzzzzazzzzzzzzzzzzzzzzzz";
    text[0][9]="zzzzzzzzzazzzzzzzzzzzzzzzzz";
    text[0][10]="zzzzzzzzzzazzzzzzzzzzzzzzzz";
    text[0][11]="zzzzzzzzzzzazzzzzzzzzzzzzzz";
    text[0][12]="zzzzzzzzzzzzazzzzzzzzzzzzzz";
    text[0][13]="zzzzzzzzzzzzzazzzzzzzzzzzzz";
    text[0][14]="zzzzzzzzzzzzzzazzzzzzzzzzzz";
    text[0][15]="zzzzzzzzzzzzzzzazzzzzzzzzzz";
    text[0][16]="zzzzzzzzzzzzzzzzazzzzzzzzzz";
    text[0][17]="zzzzzzzzzzzzzzzzzazzzzzzzzz";
    text[0][18]="zzzzzzzzzzzzzzzzzzazzzzzzzz";
    text[0][19]="zzzzzzzzzzzzzzzzzzzazzzzzzz";
    text[0][20]="zzzzzzzzzzzzzzzzzzzzazzzzzz";
    text[0][21]="zzzzzzzzzzzzzzzzzzzzzazzzzz";
    text[0][22]="zzzzzzzzzzzzzzzzzzzzzzazzzz";
    text[0][23]="zzzzzzzzzzzzzzzzzzzzzzzazzz";
    text[0][24]="zzzzzzzzzzzzzzzzzzzzzzzzazz";
    text[0][25]="zzzzzzzzzzzzzzzzzzzzzzzzzaz";
    text[0][26]="zzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1][0]="aBzzzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][1]="zaBzzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][2]="zzaBzzzzzzzzzzzzzzzzzzzzzzz";
    text[1][3]="zzzaBzzzzzzzzzzzzzzzzzzzzzz";
    text[1][4]="zzzzaBzzzzzzzzzzzzzzzzzzzzz";
    text[1][5]="zzzzzaBzzzzzzzzzzzzzzzzzzzz";
    text[1][6]="zzzzzzaBzzzzzzzzzzzzzzzzzzz";
    text[1][7]="zzzzzzzaBzzzzzzzzzzzzzzzzzz";
    text[1][8]="zzzzzzzzaBzzzzzzzzzzzzzzzzz";
    text[1][9]="zzzzzzzzzaBzzzzzzzzzzzzzzzz";
    text[1][10]="zzzzzzzzzzaBzzzzzzzzzzzzzzz";
    text[1][11]="zzzzzzzzzzzaBzzzzzzzzzzzzzz";
    text[1][12]="zzzzzzzzzzzzaBzzzzzzzzzzzzz";
    text[1][13]="zzzzzzzzzzzzzaBzzzzzzzzzzzz";
    text[1][14]="zzzzzzzzzzzzzzaBzzzzzzzzzzz";
    text[1][15]="zzzzzzzzzzzzzzzaBzzzzzzzzzz";
    text[1][16]="zzzzzzzzzzzzzzzzaBzzzzzzzzz";
    text[1][17]="zzzzzzzzzzzzzzzzzaBzzzzzzzz";
    text[1][18]="zzzzzzzzzzzzzzzzzzaBzzzzzzz";
    text[1][19]="zzzzzzzzzzzzzzzzzzzaBzzzzzz";
    text[1][20]="zzzzzzzzzzzzzzzzzzzzaBzzzzz";
    text[1][21]="zzzzzzzzzzzzzzzzzzzzzaBzzzz";
    text[1][22]="zzzzzzzzzzzzzzzzzzzzzzaBzzz";
    text[1][23]="zzzzzzzzzzzzzzzzzzzzzzzaBzz";
    text[1][24]="zzzzzzzzzzzzzzzzzzzzzzzzaBz";
    text[1][25]="zzzzzzzzzzzzzzzzzzzzzzzzzaB";
    text[2][0]="aBczzzzzzzzzzzzzzzzzzzzzzzz";
    text[2][1]="zaBczzzzzzzzzzzzzzzzzzzzzzz";
    text[2][2]="zzaBczzzzzzzzzzzzzzzzzzzzzz";
    text[2][3]="zzzaBczzzzzzzzzzzzzzzzzzzzz";
    text[2][4]="zzzzaBczzzzzzzzzzzzzzzzzzzz";
    text[2][5]="zzzzzaBczzzzzzzzzzzzzzzzzzz";
    text[2][6]="zzzzzzaBczzzzzzzzzzzzzzzzzz";
    text[2][7]="zzzzzzzaBczzzzzzzzzzzzzzzzz";
    text[2][8]="zzzzzzzzaBczzzzzzzzzzzzzzzz";
    text[2][9]="zzzzzzzzzaBczzzzzzzzzzzzzzz";
    text[2][10]="zzzzzzzzzzaBczzzzzzzzzzzzzz";
    text[2][11]="zzzzzzzzzzzaBczzzzzzzzzzzzz";
    text[2][12]="zzzzzzzzzzzzaBczzzzzzzzzzzz";
    text[2][13]="zzzzzzzzzzzzzaBczzzzzzzzzzz";
    text[2][14]="zzzzzzzzzzzzzzaBczzzzzzzzzz";
    text[2][15]="zzzzzzzzzzzzzzzaBczzzzzzzzz";
    text[2][16]="zzzzzzzzzzzzzzzzaBczzzzzzzz";
    text[2][17]="zzzzzzzzzzzzzzzzzaBczzzzzzz";
    text[2][18]="zzzzzzzzzzzzzzzzzzaBczzzzzz";
    text[2][19]="zzzzzzzzzzzzzzzzzzzaBczzzzz";
    text[2][20]="zzzzzzzzzzzzzzzzzzzzaBczzzz";
    text[2][21]="zzzzzzzzzzzzzzzzzzzzzaBczzz";
    text[2][22]="zzzzzzzzzzzzzzzzzzzzzzaBczz";
    text[2][23]="zzzzzzzzzzzzzzzzzzzzzzzaBcz";
    text[2][24]="zzzzzzzzzzzzzzzzzzzzzzzzaBc";
    text[3][0]="aBcDzzzzzzzzzzzzzzzzzzzzzzz";
    text[3][1]="zaBcDzzzzzzzzzzzzzzzzzzzzzz";
    text[3][2]="zzaBcDzzzzzzzzzzzzzzzzzzzzz";
    text[3][3]="zzzaBcDzzzzzzzzzzzzzzzzzzzz";
    text[3][4]="zzzzaBcDzzzzzzzzzzzzzzzzzzz";
    text[3][5]="zzzzzaBcDzzzzzzzzzzzzzzzzzz";
    text[3][6]="zzzzzzaBcDzzzzzzzzzzzzzzzzz";
    text[3][7]="zzzzzzzaBcDzzzzzzzzzzzzzzzz";
    text[3][8]="zzzzzzzzaBcDzzzzzzzzzzzzzzz";
    text[3][9]="zzzzzzzzzaBcDzzzzzzzzzzzzzz";
    text[3][10]="zzzzzzzzzzaBcDzzzzzzzzzzzzz";
    text[3][11]="zzzzzzzzzzzaBcDzzzzzzzzzzzz";
    text[3][12]="zzzzzzzzzzzzaBcDzzzzzzzzzzz";
    text[3][13]="zzzzzzzzzzzzzaBcDzzzzzzzzzz";
    text[3][14]="zzzzzzzzzzzzzzaBcDzzzzzzzzz";
    text[3][15]="zzzzzzzzzzzzzzzaBcDzzzzzzzz";
    text[3][16]="zzzzzzzzzzzzzzzzaBcDzzzzzzz";
    text[3][17]="zzzzzzzzzzzzzzzzzaBcDzzzzzz";
    text[3][18]="zzzzzzzzzzzzzzzzzzaBcDzzzzz";
    text[3][19]="zzzzzzzzzzzzzzzzzzzaBcDzzzz";
    text[3][20]="zzzzzzzzzzzzzzzzzzzzaBcDzzz";
    text[3][21]="zzzzzzzzzzzzzzzzzzzzzaBcDzz";
    text[3][22]="zzzzzzzzzzzzzzzzzzzzzzaBcDz";
    text[3][23]="zzzzzzzzzzzzzzzzzzzzzzzaBcD";
    text[4][0]="aBcDezzzzzzzzzzzzzzzzzzzzzz";
    text[4][1]="zaBcDezzzzzzzzzzzzzzzzzzzzz";
    text[4][2]="zzaBcDezzzzzzzzzzzzzzzzzzzz";
    text[4][3]="zzzaBcDezzzzzzzzzzzzzzzzzzz";
    text[4][4]="zzzzaBcDezzzzzzzzzzzzzzzzzz";
    text[4][5]="zzzzzaBcDezzzzzzzzzzzzzzzzz";
    text[4][6]="zzzzzzaBcDezzzzzzzzzzzzzzzz";
    text[4][7]="zzzzzzzaBcDezzzzzzzzzzzzzzz";
    text[4][8]="zzzzzzzzaBcDezzzzzzzzzzzzzz";
    text[4][9]="zzzzzzzzzaBcDezzzzzzzzzzzzz";
    text[4][10]="zzzzzzzzzzaBcDezzzzzzzzzzzz";
    text[4][11]="zzzzzzzzzzzaBcDezzzzzzzzzzz";
    text[4][12]="zzzzzzzzzzzzaBcDezzzzzzzzzz";
    text[4][13]="zzzzzzzzzzzzzaBcDezzzzzzzzz";
    text[4][14]="zzzzzzzzzzzzzzaBcDezzzzzzzz";
    text[4][15]="zzzzzzzzzzzzzzzaBcDezzzzzzz";
    text[4][16]="zzzzzzzzzzzzzzzzaBcDezzzzzz";
    text[4][17]="zzzzzzzzzzzzzzzzzaBcDezzzzz";
    text[4][18]="zzzzzzzzzzzzzzzzzzaBcDezzzz";
    text[4][19]="zzzzzzzzzzzzzzzzzzzaBcDezzz";
    text[4][20]="zzzzzzzzzzzzzzzzzzzzaBcDezz";
    text[4][21]="zzzzzzzzzzzzzzzzzzzzzaBcDez";
    text[4][22]="zzzzzzzzzzzzzzzzzzzzzzaBcDe";
    text[5][0]="aBcDeFzzzzzzzzzzzzzzzzzzzzz";
    text[5][1]="zaBcDeFzzzzzzzzzzzzzzzzzzzz";
    text[5][2]="zzaBcDeFzzzzzzzzzzzzzzzzzzz";
    text[5][3]="zzzaBcDeFzzzzzzzzzzzzzzzzzz";
    text[5][4]="zzzzaBcDeFzzzzzzzzzzzzzzzzz";
    text[5][5]="zzzzzaBcDeFzzzzzzzzzzzzzzzz";
    text[5][6]="zzzzzzaBcDeFzzzzzzzzzzzzzzz";
    text[5][7]="zzzzzzzaBcDeFzzzzzzzzzzzzzz";
    text[5][8]="zzzzzzzzaBcDeFzzzzzzzzzzzzz";
    text[5][9]="zzzzzzzzzaBcDeFzzzzzzzzzzzz";
    text[5][10]="zzzzzzzzzzaBcDeFzzzzzzzzzzz";
    text[5][11]="zzzzzzzzzzzaBcDeFzzzzzzzzzz";
    text[5][12]="zzzzzzzzzzzzaBcDeFzzzzzzzzz";
    text[5][13]="zzzzzzzzzzzzzaBcDeFzzzzzzzz";
    text[5][14]="zzzzzzzzzzzzzzaBcDeFzzzzzzz";
    text[5][15]="zzzzzzzzzzzzzzzaBcDeFzzzzzz";
    text[5][16]="zzzzzzzzzzzzzzzzaBcDeFzzzzz";
    text[5][17]="zzzzzzzzzzzzzzzzzaBcDeFzzzz";
    text[5][18]="zzzzzzzzzzzzzzzzzzaBcDeFzzz";
    text[5][19]="zzzzzzzzzzzzzzzzzzzaBcDeFzz";
    text[5][20]="zzzzzzzzzzzzzzzzzzzzaBcDeFz";
    text[5][21]="zzzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6][0]="aBcDeFgzzzzzzzzzzzzzzzzzzzz";
    text[6][1]="zaBcDeFgzzzzzzzzzzzzzzzzzzz";
    text[6][2]="zzaBcDeFgzzzzzzzzzzzzzzzzzz";
    text[6][3]="zzzaBcDeFgzzzzzzzzzzzzzzzzz";
    text[6][4]="zzzzaBcDeFgzzzzzzzzzzzzzzzz";
    text[6][5]="zzzzzaBcDeFgzzzzzzzzzzzzzzz";
    text[6][6]="zzzzzzaBcDeFgzzzzzzzzzzzzzz";
    text[6][7]="zzzzzzzaBcDeFgzzzzzzzzzzzzz";
    text[6][8]="zzzzzzzzaBcDeFgzzzzzzzzzzzz";
    text[6][9]="zzzzzzzzzaBcDeFgzzzzzzzzzzz";
    text[6][10]="zzzzzzzzzzaBcDeFgzzzzzzzzzz";
    text[6][11]="zzzzzzzzzzzaBcDeFgzzzzzzzzz";
    text[6][12]="zzzzzzzzzzzzaBcDeFgzzzzzzzz";
    text[6][13]="zzzzzzzzzzzzzaBcDeFgzzzzzzz";
    text[6][14]="zzzzzzzzzzzzzzaBcDeFgzzzzzz";
    text[6][15]="zzzzzzzzzzzzzzzaBcDeFgzzzzz";
    text[6][16]="zzzzzzzzzzzzzzzzaBcDeFgzzzz";
    text[6][17]="zzzzzzzzzzzzzzzzzaBcDeFgzzz";
    text[6][18]="zzzzzzzzzzzzzzzzzzaBcDeFgzz";
    text[6][19]="zzzzzzzzzzzzzzzzzzzaBcDeFgz";
    text[6][20]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7][0]="aBcDeFgHzzzzzzzzzzzzzzzzzzz";
    text[7][1]="zaBcDeFgHzzzzzzzzzzzzzzzzzz";
    text[7][2]="zzaBcDeFgHzzzzzzzzzzzzzzzzz";
    text[7][3]="zzzaBcDeFgHzzzzzzzzzzzzzzzz";
    text[7][4]="zzzzaBcDeFgHzzzzzzzzzzzzzzz";
    text[7][5]="zzzzzaBcDeFgHzzzzzzzzzzzzzz";
    text[7][6]="zzzzzzaBcDeFgHzzzzzzzzzzzzz";
    text[7][7]="zzzzzzzaBcDeFgHzzzzzzzzzzzz";
    text[7][8]="zzzzzzzzaBcDeFgHzzzzzzzzzzz";
    text[7][9]="zzzzzzzzzaBcDeFgHzzzzzzzzzz";
    text[7][10]="zzzzzzzzzzaBcDeFgHzzzzzzzzz";
    text[7][11]="zzzzzzzzzzzaBcDeFgHzzzzzzzz";
    text[7][12]="zzzzzzzzzzzzaBcDeFgHzzzzzzz";
    text[7][13]="zzzzzzzzzzzzzaBcDeFgHzzzzzz";
    text[7][14]="zzzzzzzzzzzzzzaBcDeFgHzzzzz";
    text[7][15]="zzzzzzzzzzzzzzzaBcDeFgHzzzz";
    text[7][16]="zzzzzzzzzzzzzzzzaBcDeFgHzzz";
    text[7][17]="zzzzzzzzzzzzzzzzzaBcDeFgHzz";
    text[7][18]="zzzzzzzzzzzzzzzzzzaBcDeFgHz";
    text[7][19]="zzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8][0]="aBcDeFgHizzzzzzzzzzzzzzzzzz";
    text[8][1]="zaBcDeFgHizzzzzzzzzzzzzzzzz";
    text[8][2]="zzaBcDeFgHizzzzzzzzzzzzzzzz";
    text[8][3]="zzzaBcDeFgHizzzzzzzzzzzzzzz";
    text[8][4]="zzzzaBcDeFgHizzzzzzzzzzzzzz";
    text[8][5]="zzzzzaBcDeFgHizzzzzzzzzzzzz";
    text[8][6]="zzzzzzaBcDeFgHizzzzzzzzzzzz";
    text[8][7]="zzzzzzzaBcDeFgHizzzzzzzzzzz";
    text[8][8]="zzzzzzzzaBcDeFgHizzzzzzzzzz";
    text[8][9]="zzzzzzzzzaBcDeFgHizzzzzzzzz";
    text[8][10]="zzzzzzzzzzaBcDeFgHizzzzzzzz";
    text[8][11]="zzzzzzzzzzzaBcDeFgHizzzzzzz";
    text[8][12]="zzzzzzzzzzzzaBcDeFgHizzzzzz";
    text[8][13]="zzzzzzzzzzzzzaBcDeFgHizzzzz";
    text[8][14]="zzzzzzzzzzzzzzaBcDeFgHizzzz";
    text[8][15]="zzzzzzzzzzzzzzzaBcDeFgHizzz";
    text[8][16]="zzzzzzzzzzzzzzzzaBcDeFgHizz";
    text[8][17]="zzzzzzzzzzzzzzzzzaBcDeFgHiz";
    text[8][18]="zzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9][0]="aBcDeFgHiJzzzzzzzzzzzzzzzzz";
    text[9][1]="zaBcDeFgHiJzzzzzzzzzzzzzzzz";
    text[9][2]="zzaBcDeFgHiJzzzzzzzzzzzzzzz";
    text[9][3]="zzzaBcDeFgHiJzzzzzzzzzzzzzz";
    text[9][4]="zzzzaBcDeFgHiJzzzzzzzzzzzzz";
    text[9][5]="zzzzzaBcDeFgHiJzzzzzzzzzzzz";
    text[9][6]="zzzzzzaBcDeFgHiJzzzzzzzzzzz";
    text[9][7]="zzzzzzzaBcDeFgHiJzzzzzzzzzz";
    text[9][8]="zzzzzzzzaBcDeFgHiJzzzzzzzzz";
    text[9][9]="zzzzzzzzzaBcDeFgHiJzzzzzzzz";
    text[9][10]="zzzzzzzzzzaBcDeFgHiJzzzzzzz";
    text[9][11]="zzzzzzzzzzzaBcDeFgHiJzzzzzz";
    text[9][12]="zzzzzzzzzzzzaBcDeFgHiJzzzzz";
    text[9][13]="zzzzzzzzzzzzzaBcDeFgHiJzzzz";
    text[9][14]="zzzzzzzzzzzzzzaBcDeFgHiJzzz";
    text[9][15]="zzzzzzzzzzzzzzzaBcDeFgHiJzz";
    text[9][16]="zzzzzzzzzzzzzzzzaBcDeFgHiJz";
    text[9][17]="zzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10][0]="aBcDeFgHiJkzzzzzzzzzzzzzzzz";
    text[10][1]="zaBcDeFgHiJkzzzzzzzzzzzzzzz";
    text[10][2]="zzaBcDeFgHiJkzzzzzzzzzzzzzz";
    text[10][3]="zzzaBcDeFgHiJkzzzzzzzzzzzzz";
    text[10][4]="zzzzaBcDeFgHiJkzzzzzzzzzzzz";
    text[10][5]="zzzzzaBcDeFgHiJkzzzzzzzzzzz";
    text[10][6]="zzzzzzaBcDeFgHiJkzzzzzzzzzz";
    text[10][7]="zzzzzzzaBcDeFgHiJkzzzzzzzzz";
    text[10][8]="zzzzzzzzaBcDeFgHiJkzzzzzzzz";
    text[10][9]="zzzzzzzzzaBcDeFgHiJkzzzzzzz";
    text[10][10]="zzzzzzzzzzaBcDeFgHiJkzzzzzz";
    text[10][11]="zzzzzzzzzzzaBcDeFgHiJkzzzzz";
    text[10][12]="zzzzzzzzzzzzaBcDeFgHiJkzzzz";
    text[10][13]="zzzzzzzzzzzzzaBcDeFgHiJkzzz";
    text[10][14]="zzzzzzzzzzzzzzaBcDeFgHiJkzz";
    text[10][15]="zzzzzzzzzzzzzzzaBcDeFgHiJkz";
    text[10][16]="zzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11][0]="aBcDeFgHiJkLzzzzzzzzzzzzzzz";
    text[11][1]="zaBcDeFgHiJkLzzzzzzzzzzzzzz";
    text[11][2]="zzaBcDeFgHiJkLzzzzzzzzzzzzz";
    text[11][3]="zzzaBcDeFgHiJkLzzzzzzzzzzzz";
    text[11][4]="zzzzaBcDeFgHiJkLzzzzzzzzzzz";
    text[11][5]="zzzzzaBcDeFgHiJkLzzzzzzzzzz";
    text[11][6]="zzzzzzaBcDeFgHiJkLzzzzzzzzz";
    text[11][7]="zzzzzzzaBcDeFgHiJkLzzzzzzzz";
    text[11][8]="zzzzzzzzaBcDeFgHiJkLzzzzzzz";
    text[11][9]="zzzzzzzzzaBcDeFgHiJkLzzzzzz";
    text[11][10]="zzzzzzzzzzaBcDeFgHiJkLzzzzz";
    text[11][11]="zzzzzzzzzzzaBcDeFgHiJkLzzzz";
    text[11][12]="zzzzzzzzzzzzaBcDeFgHiJkLzzz";
    text[11][13]="zzzzzzzzzzzzzaBcDeFgHiJkLzz";
    text[11][14]="zzzzzzzzzzzzzzaBcDeFgHiJkLz";
    text[11][15]="zzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12][0]="aBcDeFgHiJkLmzzzzzzzzzzzzzz";
    text[12][1]="zaBcDeFgHiJkLmzzzzzzzzzzzzz";
    text[12][2]="zzaBcDeFgHiJkLmzzzzzzzzzzzz";
    text[12][3]="zzzaBcDeFgHiJkLmzzzzzzzzzzz";
    text[12][4]="zzzzaBcDeFgHiJkLmzzzzzzzzzz";
    text[12][5]="zzzzzaBcDeFgHiJkLmzzzzzzzzz";
    text[12][6]="zzzzzzaBcDeFgHiJkLmzzzzzzzz";
    text[12][7]="zzzzzzzaBcDeFgHiJkLmzzzzzzz";
    text[12][8]="zzzzzzzzaBcDeFgHiJkLmzzzzzz";
    text[12][9]="zzzzzzzzzaBcDeFgHiJkLmzzzzz";
    text[12][10]="zzzzzzzzzzaBcDeFgHiJkLmzzzz";
    text[12][11]="zzzzzzzzzzzaBcDeFgHiJkLmzzz";
    text[12][12]="zzzzzzzzzzzzaBcDeFgHiJkLmzz";
    text[12][13]="zzzzzzzzzzzzzaBcDeFgHiJkLmz";
    text[12][14]="zzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13][0]="aBcDeFgHiJkLmNzzzzzzzzzzzzz";
    text[13][1]="zaBcDeFgHiJkLmNzzzzzzzzzzzz";
    text[13][2]="zzaBcDeFgHiJkLmNzzzzzzzzzzz";
    text[13][3]="zzzaBcDeFgHiJkLmNzzzzzzzzzz";
    text[13][4]="zzzzaBcDeFgHiJkLmNzzzzzzzzz";
    text[13][5]="zzzzzaBcDeFgHiJkLmNzzzzzzzz";
    text[13][6]="zzzzzzaBcDeFgHiJkLmNzzzzzzz";
    text[13][7]="zzzzzzzaBcDeFgHiJkLmNzzzzzz";
    text[13][8]="zzzzzzzzaBcDeFgHiJkLmNzzzzz";
    text[13][9]="zzzzzzzzzaBcDeFgHiJkLmNzzzz";
    text[13][10]="zzzzzzzzzzaBcDeFgHiJkLmNzzz";
    text[13][11]="zzzzzzzzzzzaBcDeFgHiJkLmNzz";
    text[13][12]="zzzzzzzzzzzzaBcDeFgHiJkLmNz";
    text[13][13]="zzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14][0]="aBcDeFgHiJkLmNozzzzzzzzzzzz";
    text[14][1]="zaBcDeFgHiJkLmNozzzzzzzzzzz";
    text[14][2]="zzaBcDeFgHiJkLmNozzzzzzzzzz";
    text[14][3]="zzzaBcDeFgHiJkLmNozzzzzzzzz";
    text[14][4]="zzzzaBcDeFgHiJkLmNozzzzzzzz";
    text[14][5]="zzzzzaBcDeFgHiJkLmNozzzzzzz";
    text[14][6]="zzzzzzaBcDeFgHiJkLmNozzzzzz";
    text[14][7]="zzzzzzzaBcDeFgHiJkLmNozzzzz";
    text[14][8]="zzzzzzzzaBcDeFgHiJkLmNozzzz";
    text[14][9]="zzzzzzzzzaBcDeFgHiJkLmNozzz";
    text[14][10]="zzzzzzzzzzaBcDeFgHiJkLmNozz";
    text[14][11]="zzzzzzzzzzzaBcDeFgHiJkLmNoz";
    text[14][12]="zzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15][0]="aBcDeFgHiJkLmNoPzzzzzzzzzzz";
    text[15][1]="zaBcDeFgHiJkLmNoPzzzzzzzzzz";
    text[15][2]="zzaBcDeFgHiJkLmNoPzzzzzzzzz";
    text[15][3]="zzzaBcDeFgHiJkLmNoPzzzzzzzz";
    text[15][4]="zzzzaBcDeFgHiJkLmNoPzzzzzzz";
    text[15][5]="zzzzzaBcDeFgHiJkLmNoPzzzzzz";
    text[15][6]="zzzzzzaBcDeFgHiJkLmNoPzzzzz";
    text[15][7]="zzzzzzzaBcDeFgHiJkLmNoPzzzz";
    text[15][8]="zzzzzzzzaBcDeFgHiJkLmNoPzzz";
    text[15][9]="zzzzzzzzzaBcDeFgHiJkLmNoPzz";
    text[15][10]="zzzzzzzzzzaBcDeFgHiJkLmNoPz";
    text[15][11]="zzzzzzzzzzzaBcDeFgHiJkLmNoP";
    text[16][0]="aBcDeFgHiJkLmNoPqzzzzzzzzzz";
    text[16][1]="zaBcDeFgHiJkLmNoPqzzzzzzzzz";
    text[16][2]="zzaBcDeFgHiJkLmNoPqzzzzzzzz";
    text[16][3]="zzzaBcDeFgHiJkLmNoPqzzzzzzz";
    text[16][4]="zzzzaBcDeFgHiJkLmNoPqzzzzzz";
    text[16][5]="zzzzzaBcDeFgHiJkLmNoPqzzzzz";
    text[16][6]="zzzzzzaBcDeFgHiJkLmNoPqzzzz";
    text[16][7]="zzzzzzzaBcDeFgHiJkLmNoPqzzz";
    text[16][8]="zzzzzzzzaBcDeFgHiJkLmNoPqzz";
    text[16][9]="zzzzzzzzzaBcDeFgHiJkLmNoPqz";
    text[16][10]="zzzzzzzzzzaBcDeFgHiJkLmNoPq";
    text[17][0]="aBcDeFgHiJkLmNoPqRzzzzzzzzz";
    text[17][1]="zaBcDeFgHiJkLmNoPqRzzzzzzzz";
    text[17][2]="zzaBcDeFgHiJkLmNoPqRzzzzzzz";
    text[17][3]="zzzaBcDeFgHiJkLmNoPqRzzzzzz";
    text[17][4]="zzzzaBcDeFgHiJkLmNoPqRzzzzz";
    text[17][5]="zzzzzaBcDeFgHiJkLmNoPqRzzzz";
    text[17][6]="zzzzzzaBcDeFgHiJkLmNoPqRzzz";
    text[17][7]="zzzzzzzaBcDeFgHiJkLmNoPqRzz";
    text[17][8]="zzzzzzzzaBcDeFgHiJkLmNoPqRz";
    text[17][9]="zzzzzzzzzaBcDeFgHiJkLmNoPqR";
    text[18][0]="aBcDeFgHiJkLmNoPqRszzzzzzzz";
    text[18][1]="zaBcDeFgHiJkLmNoPqRszzzzzzz";
    text[18][2]="zzaBcDeFgHiJkLmNoPqRszzzzzz";
    text[18][3]="zzzaBcDeFgHiJkLmNoPqRszzzzz";
    text[18][4]="zzzzaBcDeFgHiJkLmNoPqRszzzz";
    text[18][5]="zzzzzaBcDeFgHiJkLmNoPqRszzz";
    text[18][6]="zzzzzzaBcDeFgHiJkLmNoPqRszz";
    text[18][7]="zzzzzzzaBcDeFgHiJkLmNoPqRsz";
    text[18][8]="zzzzzzzzaBcDeFgHiJkLmNoPqRs";
    text[19][0]="aBcDeFgHiJkLmNoPqRsTzzzzzzz";
    text[19][1]="zaBcDeFgHiJkLmNoPqRsTzzzzzz";
    text[19][2]="zzaBcDeFgHiJkLmNoPqRsTzzzzz";
    text[19][3]="zzzaBcDeFgHiJkLmNoPqRsTzzzz";
    text[19][4]="zzzzaBcDeFgHiJkLmNoPqRsTzzz";
    text[19][5]="zzzzzaBcDeFgHiJkLmNoPqRsTzz";
    text[19][6]="zzzzzzaBcDeFgHiJkLmNoPqRsTz";
    text[19][7]="zzzzzzzaBcDeFgHiJkLmNoPqRsT";
    text[20][0]="aBcDeFgHiJkLmNoPqRsTuzzzzzz";
    text[20][1]="zaBcDeFgHiJkLmNoPqRsTuzzzzz";
    text[20][2]="zzaBcDeFgHiJkLmNoPqRsTuzzzz";
    text[20][3]="zzzaBcDeFgHiJkLmNoPqRsTuzzz";
    text[20][4]="zzzzaBcDeFgHiJkLmNoPqRsTuzz";
    text[20][5]="zzzzzaBcDeFgHiJkLmNoPqRsTuz";
    text[20][6]="zzzzzzaBcDeFgHiJkLmNoPqRsTu";
    text[21][0]="aBcDeFgHiJkLmNoPqRsTuVzzzzz";
    text[21][1]="zaBcDeFgHiJkLmNoPqRsTuVzzzz";
    text[21][2]="zzaBcDeFgHiJkLmNoPqRsTuVzzz";
    text[21][3]="zzzaBcDeFgHiJkLmNoPqRsTuVzz";
    text[21][4]="zzzzaBcDeFgHiJkLmNoPqRsTuVz";
    text[21][5]="zzzzzaBcDeFgHiJkLmNoPqRsTuV";
    text[22][0]="aBcDeFgHiJkLmNoPqRsTuVwzzzz";
    text[22][1]="zaBcDeFgHiJkLmNoPqRsTuVwzzz";
    text[22][2]="zzaBcDeFgHiJkLmNoPqRsTuVwzz";
    text[22][3]="zzzaBcDeFgHiJkLmNoPqRsTuVwz";
    text[22][4]="zzzzaBcDeFgHiJkLmNoPqRsTuVw";
    text[23][0]="aBcDeFgHiJkLmNoPqRsTuVwXzzz";
    text[23][1]="zaBcDeFgHiJkLmNoPqRsTuVwXzz";
    text[23][2]="zzaBcDeFgHiJkLmNoPqRsTuVwXz";
    text[23][3]="zzzaBcDeFgHiJkLmNoPqRsTuVwX";
    text[24][0]="aBcDeFgHiJkLmNoPqRsTuVwXyzz";
    text[24][1]="zaBcDeFgHiJkLmNoPqRsTuVwXyz";
    text[24][2]="zzaBcDeFgHiJkLmNoPqRsTuVwXy";
    text[25][0]="aBcDeFgHiJkLmNoPqRsTuVwXyZz";
    text[25][1]="zaBcDeFgHiJkLmNoPqRsTuVwXyZ";

    char *needle[26];
    needle[0]="A";
    needle[1]="Ab";
    needle[2]="AbC";
    needle[3]="AbCd";
    needle[4]="AbCdE";
    needle[5]="AbCdEf";
    needle[6]="AbCdEfG";
    needle[7]="AbCdEfGh";
    needle[8]="AbCdEfGhI";
    needle[9]="AbCdEfGhIJ";
    needle[10]="AbCdEfGhIjK";
    needle[11]="AbCdEfGhIjKl";
    needle[12]="AbCdEfGhIjKlM";
    needle[13]="AbCdEfGhIjKlMn";
    needle[14]="AbCdEfGhIjKlMnO";
    needle[15]="AbCdEfGhIjKlMnOp";
    needle[16]="AbCdEfGhIjKlMnOpQ";
    needle[17]="AbCdEfGhIjKlMnOpQr";
    needle[18]="AbCdEfGhIjKlMnOpQrS";
    needle[19]="AbCdEfGhIjKlMnOpQrSt";
    needle[20]="AbCdEfGhIjKlMnOpQrStU";
    needle[21]="AbCdEfGhIjKlMnOpQrStUv";
    needle[22]="AbCdEfGhIjKlMnOpQrStUvW";
    needle[23]="AbCdEfGhIjKlMnOpQrStUvWx";
    needle[24]="AbCdEfGhIjKlMnOpQrStUvWxY";
    needle[25]="AbCdEfGhIjKlMnOpQrStUvWxYZ";

    int i, j;
    uint8_t *found = NULL;
    for (i = 0; i < 26; i++) {
        for (j = 0; j <= (26-i); j++) {
            found = BasicSearchNocaseWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error1 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
            found = Bs2bmNocaseWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error2 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
            found = BoyerMooreNocaseWrapper((uint8_t *)text[i][j], (uint8_t *)needle[i], 1);
            if (found == 0) {
                printf("Error3 searching for %s in text %s\n", needle[i], text[i][j]);
                return 0;
            }
        }
    }
    return 1;
}

/**
 * \test Give some stats
 */
int UtilSpmSearchStatsTest01()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1]="aaaaaaaaazaaaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaazaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaazaaaaaraaaaazaaaaaaazaaaaaaaaaaaaaazaaaaaaaazaaaaaaaaazaaaaaaaaaaaaB";
    text[2]="aBaBaBaBaBaBaBaBazaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBzBaBaBaBaBaBaBzBaBaBaBaBzBaBaBaBaBaBzBaBaBaBaBaBzBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBazaBaBaBaBaBc";
    text[3]="aBcaBcaBcaBcaBczBcaBcaBzaBcaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBzaBcaBcaBcazcaBcaBcaBcaBcaBcD";
    text[4]="aBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDzBcDaBcDaBcDaBcDzBcDaBcDaBczaBcDaBcDaBczaBcDaBcDaBcDaBcDaBzDaBcDaBcDaBcDaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDaBcDaBzDaBcDaBcDaBcDaBzDaBcDaBcDaBzDaBcDaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDazcDaBcDaBcDaBcDaBcDzBcDaBcDaBcDaBcDaBcDaBcDe";
    text[5]="aBcDeaBcDeaBcDeazcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDezBcDeaBcDeaBcDzaBcDeaBcDeaBcDeazcDzaBcDeaBcDezBcDeaBzDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBczeaBcDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDzaBcDeaBcDezBcDeaBcDezBcDeaBczeaBcDeaBcDeaBzDeaBcDezBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeF";
    text[6]="aBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBczzaBcDeaBcDeaBcDzazcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDeaBczeaBcDezzzaBcDeFg";
    text[7]="aBcDeaBczeaBcDzaBcDezBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBzDzaBcDeaBcDeazcDeaBcDzaBcDeaBczeaBcDeaBcDeaBzDzaBcDeaBcDeaBcDezBcDzaBcDeaBzDeaBcDeaBcDezBcDzaBcDeaBcDeaBzDeaBcDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBrDeaBcDeaBcDezzzaBcDeFgH";
    text[8]="aBcDeaBcDeaBczzaBcDeazcDeaBcDezBcDeaBcDzaBcDeaBcDeaBcDeaBczzaBcDeaBcDeaBczeaBcDeaBcDzzBcDeaBcDeaBcDzaBczeaBcDeaBcDzaBcDeaBczeaBcDeaBcDeaBzDeaBcDeaBcDeaBzDeaBcDeaBcDzaBcDeaBcDeazcDeaBcDeaBcDzaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBczeaBcDeaBzDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHi";
    text[9]="aBcDeaBcDzaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeazcDeaBcDeaBcDzzBcDeaBcDeaBczeaBcDzaBcDezBcDeaBczeaBcDzaBcDezBcDeaBcDzaBczeaBcDeaBcDzaBcDeazcDeaBcDeaBcDzaBczeaBcDeaBcDzaBzDeaBcDeaBczeaBcDeaBcDzaBcDeaBcDeaBzDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDeaBzDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJ";
    text[10]="aBcDeaBcDeaBczeaBcDzaBczeaBcDeaBczeaBcDeaBcDzaBcDeaBcDeazcDeaBcDeaBcDeaBzDzaBcDeazcDeaBcDeazcDeaBcDzaBcDeazcDeaBcDeaBczzaBcDeaBcDeaBzDeaBcDeaBcDzaBczeaBcDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDezBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDezBcDeaBcDeaBcDeaBzDeaBcDeaBcDezzzaBcDeFgHiJk";
    text[11]="aBcDeaBcDeaBcDeaBcDeaBzDeaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDeazcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDzzBcDeaBcDeaBcDeaBcDzaBcDzaBcDeaBzDeaBcDeaBcDezBcDeaBcDeazcDeaBcDeaBcDezBcDeaBcDeaBcDeazcDeaBcDeaBzDeaBcDeaBczeaBcDeazcDeaBcDezBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkL";
    text[12]="aBcDeaBcDeaBcDeaBcDeaBzDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDeazcDeaBcDeaBcDeazcDeaBcDeaBczeaBcDeaBcDeaBcDezBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLm";
    text[13]="aBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLmN";
    text[14]="aBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDezzzaBcDeFgHiJkLmNo";
    text[15]="aBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of greater length (text with a lot of partial matches, worst case for a basic search):\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

/**
 * \test Give some stats for
 */
int UtilSpmSearchStatsTest02()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}


int UtilSpmSearchStatsTest03()
{
    char *text[16];
    text[0]="zzzzzza";
    text[1]="zzzzzzaB";
    text[2]="zzzzzzaBc";
    text[3]="zzzzzzaBcD";
    text[4]="zzzzzzaBcDe";
    text[5]="zzzzzzzzaBcDeF";
    text[6]="zzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length (badcase for):\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

/**
 * \test Give some stats
 */
int UtilSpmSearchStatsTest04()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1]="aaaaaaaaazaaaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaazaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaaaaaaaaazaaaaaaaaaaaaaaaaazaaaaaaaaazaaaaaaaaaazaaaaaraaaaazaaaaaaazaaaaaaaaaaaaaazaaaaaaaazaaaaaaaaazaaaaaaaaaaaaB";
    text[2]="aBaBaBaBaBaBaBaBazaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBzBaBaBaBaBaBaBzBaBaBaBaBzBaBaBaBaBaBzBaBaBaBaBaBzBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBaBaBzBaBaBaBaBaBaBaBaBaBaBazaBaBaBaBaBaBaBazaBaBaBaBaBc";
    text[3]="aBcaBcaBcaBcaBczBcaBcaBzaBcaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBcaBcaBczBcaBcaBcaBcaBzaBcaBcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcazcaBcaBcaBcaBcaBcaBzaBcaBcaBcazcaBcaBcaBcaBcaBcD";
    text[4]="aBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDzBcDaBcDaBcDaBcDzBcDaBcDaBczaBcDaBcDaBczaBcDaBcDaBcDaBcDaBzDaBcDaBcDaBcDaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDaBcDaBzDaBcDaBcDaBcDaBzDaBcDaBcDaBzDaBcDaBcDaBcDaBcDaBcDaBczaBcDaBcDaBcDaBcDazcDaBcDaBcDaBcDaBcDzBcDaBcDaBcDaBcDaBcDaBcDe";
    text[5]="aBcDeaBcDeaBcDeazcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDezBcDeaBcDeaBcDzaBcDeaBcDeaBcDeazcDzaBcDeaBcDezBcDeaBzDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBczeaBcDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDzaBcDeaBcDezBcDeaBcDezBcDeaBczeaBcDeaBcDeaBzDeaBcDezBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeF";
    text[6]="aBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBczzaBcDeaBcDeaBcDzazcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDeaBczeaBcDezzzaBcDeFg";
    text[7]="aBcDeaBczeaBcDzaBcDezBcDeaBcDeaBcDeaBcDzaBzDeaBcDeaBcDeaBzDzaBcDeaBcDeazcDeaBcDzaBcDeaBczeaBcDeaBcDeaBzDzaBcDeaBcDeaBcDezBcDzaBcDeaBzDeaBcDeaBcDezBcDzaBcDeaBcDeaBzDeaBcDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBrDeaBcDeaBcDezzzaBcDeFgH";
    text[8]="aBcDeaBcDeaBczzaBcDeazcDeaBcDezBcDeaBcDzaBcDeaBcDeaBcDeaBczzaBcDeaBcDeaBczeaBcDeaBcDzzBcDeaBcDeaBcDzaBczeaBcDeaBcDzaBcDeaBczeaBcDeaBcDeaBzDeaBcDeaBcDeaBzDeaBcDeaBcDzaBcDeaBcDeazcDeaBcDeaBcDzaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeazcDeaBcDeaBcDeaBczeaBcDeaBzDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHi";
    text[9]="aBcDeaBcDzaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeazcDeaBcDeaBcDzzBcDeaBcDeaBczeaBcDzaBcDezBcDeaBczeaBcDzaBcDezBcDeaBcDzaBczeaBcDeaBcDzaBcDeazcDeaBcDeaBcDzaBczeaBcDeaBcDzaBzDeaBcDeaBczeaBcDeaBcDzaBcDeaBcDeaBzDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDeaBzDeaBcDeaBcDeazcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJ";
    text[10]="aBcDeaBcDeaBczeaBcDzaBczeaBcDeaBczeaBcDeaBcDzaBcDeaBcDeazcDeaBcDeaBcDeaBzDzaBcDeazcDeaBcDeazcDeaBcDzaBcDeazcDeaBcDeaBczzaBcDeaBcDeaBzDeaBcDeaBcDzaBczeaBcDeaBcDeaBcDeaBczeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDezBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDezBcDeaBcDeaBcDeaBzDeaBcDeaBcDezzzaBcDeFgHiJk";
    text[11]="aBcDeaBcDeaBcDeaBcDeaBzDeaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDeazcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDzaBcDzaBcDeaBcDeaBcDeaBcDzzBcDeaBcDeaBcDeaBcDzaBcDzaBcDeaBzDeaBcDeaBcDezBcDeaBcDeazcDeaBcDeaBcDezBcDeaBcDeaBcDeazcDeaBcDeaBzDeaBcDeaBczeaBcDeazcDeaBcDezBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkL";
    text[12]="aBcDeaBcDeaBcDeaBcDeaBzDeaBcDeaBzDeaBcDeaBcDezBcDeaBcDeazcDeaBcDeaBcDeazcDeaBcDeaBczeaBcDeaBcDeaBcDezBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLm";
    text[13]="aBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLmN";
    text[14]="aBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDezzzaBcDeFgHiJkLmNo";
    text[15]="aBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDzaBcDeaBcDeaBcDeaBcDezzzaBcDeFgHiJkLmNoP";


    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of greater length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i + 1);
        found = BasicSearchCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i + 1);
        found = Bs2bmCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i + 1);
        found = BoyerMooreCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with SpmSearch (Building Context):", i + 1);
        found = RawCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

/**
 * \test Give some stats for
 */
int UtilSpmSearchStatsTest05()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}


int UtilSpmSearchStatsTest06()
{
    char *text[16];
    text[0]="zzzzkzzzzzzzkzzzzzza";
    text[1]="BBBBkBBBBBBBkBBBBBaB";
    text[2]="BcBckcBcBcBckcBcBcaBc";
    text[3]="BcDBkDBcDBcDkcDBcDaBcD";
    text[4]="BcDekcDeBcDekcDezzaBcDe";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length (badcase for):\n");
    for (i = 0; i < 5; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

int UtilSpmSearchStatsTest07()
{
    char *text[16];
    text[0]="zzzza";
    text[1]="BBBaB";
    text[2]="bbaBc";
    text[3]="aaBcD";
    text[4]="aBcDe";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of real lower length (badcase for):\n");
    for (i = 0; i < 5; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

/**
 * \test Give some stats for no case algorithms
 */
int UtilSpmNocaseSearchStatsTest01()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of greater length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

int UtilSpmNocaseSearchStatsTest02()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}


int UtilSpmNocaseSearchStatsTest03()
{
    char *text[16];
    text[0]="zzzzkzzzzzzzkzzzzzza";
    text[1]="BBBBkBBBBBBBkBBBBBaB";
    text[2]="BcBckcBcBcBckcBcBcaBc";
    text[3]="BcDBkDBcDBcDkcDBcDaBcD";
    text[4]="BcDekcDeBcDekcDezzaBcDe";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length (badcase for):\n");
    for (i = 0; i < 5; i++) {
        printf("Pattern length %d with BasicSearch:", i+1);
        found = BasicSearchNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch:", i+1);
        found = Bs2bmNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch:", i+1);
        found = BoyerMooreNocaseWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

/**
 * \test Give some stats for no case algorithms
 */
int UtilSpmNocaseSearchStatsTest04()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of greater length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

int UtilSpmNocaseSearchStatsTest05()
{
    char *text[16];
    text[0]="zzzzzzzzzzzzzzzzzza";
    text[1]="zzzzzzzzzzzzzzzzzzaB";
    text[2]="zzzzzzzzzzzzzzzzzzaBc";
    text[3]="zzzzzzzzzzzzzzzzzzaBcD";
    text[4]="zzzzzzzzzzzzzzzzzzaBcDe";
    text[5]="zzzzzzzzzzzzzzzzzzzzaBcDeF";
    text[6]="zzzzzzzzzzzzzzzzzzzzaBcDeFg";
    text[7]="zzzzzzzzzzzzzzzzzzzzaBcDeFgH";
    text[8]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHi";
    text[9]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJ";
    text[10]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJk";
    text[11]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkL";
    text[12]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLm";
    text[13]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmN";
    text[14]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNo";
    text[15]="zzzzzzzzzzzzzzzzzzzzaBcDeFgHiJkLmNoP";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";
    needle[5]="aBcDeF";
    needle[6]="aBcDeFg";
    needle[7]="aBcDeFgH";
    needle[8]="aBcDeFgHi";
    needle[9]="aBcDeFgHiJ";
    needle[10]="aBcDeFgHiJk";
    needle[11]="aBcDeFgHiJkL";
    needle[12]="aBcDeFgHiJkLm";
    needle[13]="aBcDeFgHiJkLmN";
    needle[14]="aBcDeFgHiJkLmNo";
    needle[15]="aBcDeFgHiJkLmNoP";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length:\n");
    for (i = 0; i < 16; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}


int UtilSpmNocaseSearchStatsTest06()
{
    char *text[16];
    text[0]="zzzzkzzzzzzzkzzzzzza";
    text[1]="BBBBkBBBBBBBkBBBBBaB";
    text[2]="BcBckcBcBcBckcBcBcaBc";
    text[3]="BcDBkDBcDBcDkcDBcDaBcD";
    text[4]="BcDekcDeBcDekcDezzaBcDe";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of lower length (badcase for):\n");
    for (i = 0; i < 5; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

int UtilSpmNocaseSearchStatsTest07()
{
    char *text[16];
    text[0]="zzzza";
    text[1]="bbbAb";
    text[2]="bbAbC";
    text[3]="bAbCd";
    text[4]="AbCdE";

    char *needle[16];
    needle[0]="a";
    needle[1]="aB";
    needle[2]="aBc";
    needle[3]="aBcD";
    needle[4]="aBcDe";

    int i;
    uint8_t *found = NULL;
        printf("\nStats for text of real lower length (badcase for):\n");
    for (i = 0; i < 5; i++) {
        printf("Pattern length %d with BasicSearch (Building Context):", i+1);
        found = BasicSearchNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error1 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with Bs2BmSearch (Building Context):", i+1);
        found = Bs2bmNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error2 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("Pattern length %d with BoyerMooreSearch (Building Context):", i+1);
        found = BoyerMooreNocaseCtxWrapper((uint8_t *)text[i], (uint8_t *)needle[i], STATS_TIMES);
        if (found == 0) {
            printf("Error3 searching for %s in text %s\n", needle[i], text[i]);
            return 0;
        }
        printf("\n");
    }
    return 1;
}

#endif

/* Register unittests */
void UtilSpmSearchRegistertests(void)
{
#ifdef UNITTESTS
    /* Generic tests */
    UtRegisterTest("UtilSpmBasicSearchTest01", UtilSpmBasicSearchTest01, 1);
    UtRegisterTest("UtilSpmBasicSearchNocaseTest01", UtilSpmBasicSearchNocaseTest01, 1);

    UtRegisterTest("UtilSpmBs2bmSearchTest01", UtilSpmBs2bmSearchTest01, 1);
    UtRegisterTest("UtilSpmBs2bmSearchNocaseTest01", UtilSpmBs2bmSearchNocaseTest01, 1);

    UtRegisterTest("UtilSpmBoyerMooreSearchTest01", UtilSpmBoyerMooreSearchTest01, 1);
    UtRegisterTest("UtilSpmBoyerMooreSearchNocaseTest01", UtilSpmBoyerMooreSearchNocaseTest01, 1);
    UtRegisterTest("UtilSpmBoyerMooreSearchNocaseTestIssue130", UtilSpmBoyerMooreSearchNocaseTestIssue130, 1);

    UtRegisterTest("UtilSpmBs2bmSearchTest02", UtilSpmBs2bmSearchTest02, 1);
    UtRegisterTest("UtilSpmBs2bmSearchNocaseTest02", UtilSpmBs2bmSearchNocaseTest02, 1);

    UtRegisterTest("UtilSpmBasicSearchTest02", UtilSpmBasicSearchTest02, 1);
    UtRegisterTest("UtilSpmBasicSearchNocaseTest02", UtilSpmBasicSearchNocaseTest02, 1);

    UtRegisterTest("UtilSpmBoyerMooreSearchTest02", UtilSpmBoyerMooreSearchTest02, 1);
    UtRegisterTest("UtilSpmBoyerMooreSearchNocaseTest02", UtilSpmBoyerMooreSearchNocaseTest02, 1);

    /* test matches at any offset */
    UtRegisterTest("UtilSpmSearchOffsetsTest01", UtilSpmSearchOffsetsTest01, 1);
    UtRegisterTest("UtilSpmSearchOffsetsNocaseTest01", UtilSpmSearchOffsetsNocaseTest01, 1);

#ifdef ENABLE_SEARCH_STATS
    /* Give some stats searching given a prepared context (look at the wrappers) */
    UtRegisterTest("UtilSpmSearchStatsTest01", UtilSpmSearchStatsTest01, 1);
    UtRegisterTest("UtilSpmSearchStatsTest02", UtilSpmSearchStatsTest02, 1);
    UtRegisterTest("UtilSpmSearchStatsTest03", UtilSpmSearchStatsTest03, 1);

    UtRegisterTest("UtilSpmNocaseSearchStatsTest01", UtilSpmNocaseSearchStatsTest01, 1);
    UtRegisterTest("UtilSpmNocaseSearchStatsTest02", UtilSpmNocaseSearchStatsTest02, 1);
    UtRegisterTest("UtilSpmNocaseSearchStatsTest03", UtilSpmNocaseSearchStatsTest03, 1);

    /* Stats building context and searching */
    UtRegisterTest("UtilSpmSearchStatsTest04", UtilSpmSearchStatsTest04, 1);
    UtRegisterTest("UtilSpmSearchStatsTest05", UtilSpmSearchStatsTest05, 1);
    UtRegisterTest("UtilSpmSearchStatsTest06", UtilSpmSearchStatsTest06, 1);
    UtRegisterTest("UtilSpmSearchStatsTest07", UtilSpmSearchStatsTest07, 1);

    UtRegisterTest("UtilSpmNocaseSearchStatsTest04", UtilSpmNocaseSearchStatsTest04, 1);
    UtRegisterTest("UtilSpmNocaseSearchStatsTest05", UtilSpmNocaseSearchStatsTest05, 1);
    UtRegisterTest("UtilSpmNocaseSearchStatsTest06", UtilSpmNocaseSearchStatsTest06, 1);
    UtRegisterTest("UtilSpmNocaseSearchStatsTest07", UtilSpmNocaseSearchStatsTest07, 1);

#endif
#endif
}
