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
 * Boyer Moore simple pattern matcher implementation
 *
 * Boyer Moore algorithm has a really good performance. It need two arrays
 * of context for each pattern that hold applicable shifts on the text
 * to seach in, based on characters not available in the pattern
 * and combinations of characters that start a sufix of the pattern.
 * If possible, we should store the context of patterns that we are going
 * to search for multiple times, so we don't spend time on rebuilding them.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "util-spm-bm.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-memcpy.h"

static int PreBmGs(const uint8_t *x, uint16_t m, uint16_t *bmGs);
static void PreBmBc(const uint8_t *x, uint16_t m, uint16_t *bmBc);
static void PreBmBcNocase(const uint8_t *x, uint16_t m, uint16_t *bmBc);
static void BoyerMooreSuffixesNocase(const uint8_t *x, uint16_t m, 
                                     uint16_t *suff);
static void PreBmGsNocase(const uint8_t *x, uint16_t m, uint16_t *bmGs);

/**
 * \brief Given a BmCtx structure, recreate the pre/suffixes for
 *        nocase
 *
 * \retval BmCtx pointer to the already created BmCtx (with BoyerMooreCtxInit())
 * \param str pointer to the pattern string
 * \param size length of the string
 */
void BoyerMooreCtxToNocase(BmCtx *bm_ctx, uint8_t *needle, uint16_t needle_len)
{
    /* Store the content as lower case to make searching faster */
    memcpy_tolower(needle, needle, needle_len);

    /* Prepare bad chars with nocase chars */
    PreBmBcNocase(needle, needle_len, bm_ctx->bmBc);

    /* Prepare good Suffixes with nocase chars */
    PreBmGsNocase(needle, needle_len, bm_ctx->bmGs);
}

/**
 * \brief Setup a Booyer Moore context.
 *
 * \param str pointer to the pattern string
 * \param size length of the string
 * \retval BmCtx pointer to the newly created Context for the pattern
 * \initonly BoyerMoore contexts should be created at init
 */
BmCtx *BoyerMooreCtxInit(uint8_t *needle, uint16_t needle_len)
{
    BmCtx *new = SCMalloc(sizeof(BmCtx));
    if (unlikely(new == NULL)) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in BoyerMooreCtxInit. Exiting...");
        exit(EXIT_FAILURE);
    }

    /* Prepare bad chars */
    PreBmBc(needle, needle_len, new->bmBc);

    new->bmGs = SCMalloc(sizeof(uint16_t) * (needle_len + 1));
    if (new->bmGs == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Prepare good Suffixes */
    if (PreBmGs(needle, needle_len, new->bmGs) == -1) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in BooyerMooreCtxInit. Exiting...");
        exit(EXIT_FAILURE);
    }


    return new;
}

/**
 * \brief Setup a Booyer Moore context for nocase search
 *
 * \param str pointer to the pattern string
 * \param size length of the string
 * \retval BmCtx pointer to the newly created Context for the pattern
 * \initonly BoyerMoore contexts should be created at init
 */
BmCtx *BoyerMooreNocaseCtxInit(uint8_t *needle, uint16_t needle_len)
{
    BmCtx *bm_ctx = BoyerMooreCtxInit(needle, needle_len);

    BoyerMooreCtxToNocase(bm_ctx, needle, needle_len);

    return bm_ctx;
}

/**
 * \brief Free the memory allocated to Booyer Moore context.
 *
 * \param bmCtx pointer to the Context for the pattern
 */
void BoyerMooreCtxDeInit(BmCtx *bmctx)
{
    SCEnter();
    if (bmctx == NULL)
        SCReturn;

    if (bmctx->bmGs != NULL)
        SCFree(bmctx->bmGs);

    SCFree(bmctx);

    SCReturn;
}
/**
 * \brief Array setup function for bad characters that split the pattern
 *        Remember that the result array should be the length of ALPHABET_SIZE
 *
 * \param str pointer to the pattern string
 * \param size length of the string
 * \param result pointer to an empty array that will hold the badchars
 */
static void PreBmBc(const uint8_t *x, uint16_t m, uint16_t *bmBc)
{
    int32_t i;

    for (i = 0; i < 256; ++i) {
        bmBc[i] = m;
    }
    for (i = 0; i < m - 1; ++i) {
        bmBc[(unsigned char)x[i]] = m - i - 1;
    }
}

/**
 * \brief Array setup function for building prefixes (shift for valid prefixes) for boyermoore context
 *
 * \param x pointer to the pattern string
 * \param m length of the string
 * \param suff pointer to an empty array that will hold the prefixes (shifts)
 */
static void BoyerMooreSuffixes(const uint8_t *x, uint16_t m, uint16_t *suff)
{
    int32_t f = 0, g, i;
    suff[m - 1] = m;
    g = m - 1;
    for (i = m - 2; i >= 0; --i) {
        if (i > g && suff[i + m - 1 - f] < i - g)
            suff[i] = suff[i + m - 1 - f];
        else {
            if (i < g)
                g = i;
            f = i;
            while (g >= 0 && x[g] == x[g + m - 1 - f])
                --g;
            suff[i] = f - g;
        }
    }
}

/**
 * \brief Array setup function for building prefixes (shift for valid prefixes) for boyermoore context
 *
 * \param x pointer to the pattern string
 * \param m length of the string
 * \param bmGs pointer to an empty array that will hold the prefixes (shifts)
 * \retval 0 ok, -1 failed
 */
static int PreBmGs(const uint8_t *x, uint16_t m, uint16_t *bmGs)
{
    int32_t i, j;
    uint16_t suff[m + 1];

    BoyerMooreSuffixes(x, m, suff);

    for (i = 0; i < m; ++i)
        bmGs[i] = m;

    j = 0;

    for (i = m - 1; i >= -1; --i)
        if (i == -1 || suff[i] == i + 1)
            for (; j < m - 1 - i; ++j)
                if (bmGs[j] == m)
                    bmGs[j] = m - 1 - i;

    for (i = 0; i <= m - 2; ++i)
        bmGs[m - 1 - suff[i]] = m - 1 - i;
    return 0;
}

/**
 * \brief Array setup function for bad characters that split the pattern
 *        Remember that the result array should be the length of ALPHABET_SIZE
 *
 * \param str pointer to the pattern string
 * \param size length of the string
 * \param result pointer to an empty array that will hold the badchars
 */
static void PreBmBcNocase(const uint8_t *x, uint16_t m, uint16_t *bmBc)
{
    int32_t i;

    for (i = 0; i < 256; ++i) {
        bmBc[i] = m;
    }
    for (i = 0; i < m - 1; ++i) {
        bmBc[u8_tolower((unsigned char)x[i])] = m - 1 - i;
    }
}

static void BoyerMooreSuffixesNocase(const uint8_t *x, uint16_t m, 
                                     uint16_t *suff)
{
    int32_t f = 0, g, i;

    suff[m - 1] = m;
    g = m - 1;
    for (i = m - 2; i >= 0; --i) {
        if (i > g && suff[i + m - 1 - f] < i - g) {
            suff[i] = suff[i + m - 1 - f];
        } else {
            if (i < g) {
                g = i;
            }
            f = i;
            while (g >= 0 && u8_tolower(x[g]) == u8_tolower(x[g + m - 1 - f])) {
                --g;
            }
            suff[i] = f - g;
        }
    }
}

/**
 * \brief Array setup function for building prefixes (shift for valid prefixes)
 *        for boyermoore context case less
 *
 * \param x pointer to the pattern string
 * \param m length of the string
 * \param bmGs pointer to an empty array that will hold the prefixes (shifts)
 */
static void PreBmGsNocase(const uint8_t *x, uint16_t m, uint16_t *bmGs)
{
    int32_t i, j;
    uint16_t suff[m + 1];

    BoyerMooreSuffixesNocase(x, m, suff);

    for (i = 0; i < m; ++i) {
        bmGs[i] = m;
    }
    j = 0;
    for (i = m - 1; i >= 0; --i) {
        if (i == -1 || suff[i] == i + 1) {
            for (; j < m - 1 - i; ++j) {
                if (bmGs[j] == m) {
                    bmGs[j] = m - 1 - i;
                }
            }
        }
    }
    for (i = 0; i <= m - 2; ++i) {
        bmGs[m - 1 - suff[i]] = m - 1 - i;
    }
}

/**
 * \brief Boyer Moore search algorithm
 *        Is better as the pattern length increases and for big buffers to search in.
 *        The algorithm needs a context of two arrays already prepared
 *        by prep_bad_chars() and prep_good_suffix()
 *
 * \param y pointer to the buffer to search in
 * \param n length limit of the buffer
 * \param x pointer to the pattern we ar searching for
 * \param m length limit of the needle
 * \param bmBc pointer to an array of BoyerMooreSuffixes prepared by prep_good_suffix()
 * \param bmGs pointer to an array of bachars prepared by prep_bad_chars()
 *
 * \retval ptr to start of the match; NULL if no match
 */
uint8_t *BoyerMoore(uint8_t *x, uint16_t m, uint8_t *y, int32_t n, BmCtx *bm_ctx)
{
    uint16_t *bmGs = bm_ctx->bmGs;
    uint16_t *bmBc = bm_ctx->bmBc;

   int i, j, m1, m2;
#if 0
    printf("\nBad:\n");
    for (i=0;i<ALPHABET_SIZE;i++)
        printf("%c,%d ", i, bmBc[i]);

    printf("\ngood:\n");
    for (i=0;i<m;i++)
        printf("%c, %d ", x[i],bmBc[i]);
    printf("\n");
#endif
   j = 0;

   while (j <= n - m ) {
      for (i = m - 1; i >= 0 && x[i] == y[i + j]; --i);

      if (i < 0) {
         return y + j;
         //j += bmGs[0];
      } else {
 //        printf("%c", y[i+j]);
         j += (m1 = bmGs[i]) > (m2 = bmBc[y[i + j]] - m + 1 + i)? m1: m2;
//            printf("%d, %d\n", m1, m2);
      }
   }
   return NULL;
}


/**
 * \brief Boyer Moore search algorithm
 *        Is better as the pattern length increases and for big buffers to search in.
 *        The algorithm needs a context of two arrays already prepared
 *        by prep_bad_chars() and prep_good_suffix()
 *
 * \param y pointer to the buffer to search in
 * \param n length limit of the buffer
 * \param x pointer to the pattern we ar searching for
 * \param m length limit of the needle
 * \param bmBc pointer to an array of BoyerMooreSuffixes prepared by prep_good_suffix()
 * \param bmGs pointer to an array of bachars prepared by prep_bad_chars()
 *
 * \retval ptr to start of the match; NULL if no match
 */
uint8_t *BoyerMooreNocase(uint8_t *x, uint16_t m, uint8_t *y, int32_t n, BmCtx *bm_ctx)
{
    uint16_t *bmGs = bm_ctx->bmGs;
    uint16_t *bmBc = bm_ctx->bmBc;
    int i, j, m1, m2;
#if 0
    printf("\nBad:\n");
    for (i=0;i<ALPHABET_SIZE;i++)
        printf("%c,%d ", i, bmBc[i]);

    printf("\ngood:\n");
    for (i=0;i<m;i++)
        printf("%c, %d ", x[i],bmBc[i]);
    printf("\n");
#endif
    j = 0;
    while (j <= n - m ) {
        /* x is stored in lowercase. */
        for (i = m - 1; i >= 0 && x[i] == u8_tolower(y[i + j]); --i);

        if (i < 0) {
            return y + j;
        } else {
            j += (m1=bmGs[i]) > (m2=bmBc[u8_tolower(y[i + j])] - m + 1 + i)?m1:m2;
        }
   }
   return NULL;
}

