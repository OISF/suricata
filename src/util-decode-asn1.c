/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Implements ASN1 decoding (needed for the asn1 keyword, BER, CER & DER)
 */

#include "suricata.h"
#include "suricata-common.h"
#include "decode.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-print.h"

#include "util-decode-asn1.h"
#include "conf.h"

uint16_t asn1_max_frames_config = ASN1_MAX_FRAMES;

void SCAsn1LoadConfig()
{
    intmax_t value = 0;

    /** set config defaults */
    if ((ConfGetInt("asn1-max-frames", &value)) == 1) {
        asn1_max_frames_config = (uint16_t)value;
        SCLogDebug("Max stack frame set to %"PRIu16, asn1_max_frames_config);
    }

}

/**
 * \brief Decode and check the identifier information of the
 *        current node that is in extended format
 *
 * \param ac pointer to the ASN1 Context data
 *
 * \retval byte of the status of the parser
 */
static uint8_t SCAsn1GetHighTagNumber(Asn1Ctx *ac)
{
    uint8_t ret = 0;
    uint32_t tag_num = 0;

    /* If we have a high tag num, skip the id octet */
    ac->iter++;

    Asn1Node *node = ASN1CTX_CUR_NODE(ac);

    ret = SCAsn1CheckBounds(ac);
    if (ret == ASN1_PARSER_ERR) {
        ac->parser_status |= ASN1_STATUS_INVALID | ASN1_STATUS_OOB;
        return ret;
    }

    uint8_t raw_id = *ac->iter;

    tag_num += ASN1_BER_GET_HIGH_TAG_NUM(raw_id);

    if (ASN1_BER_GET_HIGH_TAG_NUM(raw_id) == 0) {
        /* Set event, invalid id */
        node->flags |= ASN1_BER_EVENT_INVALID_ID;
        ac->parser_status |= ASN1_STATUS_INVALID;
        return ASN1_PARSER_ERR;
    }

    ac->iter++;
    if (!ASN1_BER_IS_HIGH_TAG_END(raw_id)) {
        do {
            ret = SCAsn1CheckBounds(ac);
            if (ret == ASN1_PARSER_ERR) {
                ac->parser_status |= ASN1_STATUS_INVALID | ASN1_STATUS_OOB;
                return ret;
            }

            raw_id = *ac->iter;

            if ((uint64_t) ((uint64_t)tag_num +
                (uint64_t)ASN1_BER_GET_HIGH_TAG_NUM(raw_id)) > UINT32_MAX)
            {
                node->flags |= ASN1_BER_EVENT_ID_TOO_LONG;
                ac->parser_status |= ASN1_STATUS_INVALID;
                return ASN1_PARSER_ERR;
            }

            tag_num += ASN1_BER_GET_HIGH_TAG_NUM(raw_id);
            ac->iter++;
        } while (!ASN1_BER_IS_HIGH_TAG_END(raw_id));
    }
    node->id.tag_num = tag_num;

    return ASN1_PARSER_OK;
}

/**
 * \brief Decode and check the length, of the current node
 *        in definite but extended format, that we are parsing,
 *        checking invalid opts
 *
 * \param ac pointer to the ASN1 Context data
 *
 * \retval byte of the status of the parser
 */
static uint32_t SCAsn1GetLengthLongForm(Asn1Ctx *ac)
{
    uint8_t raw_len = *ac->iter;
    uint8_t ret = 0;
    uint32_t content_len = 0;
    uint8_t oct_len = ASN1_BER_GET_LONG_LEN_OCTETS(raw_len);
    uint8_t i = 0;

    Asn1Node *node = ASN1CTX_CUR_NODE(ac);

    for (; i < oct_len; i++) {
        ac->iter++;

        ret = SCAsn1CheckBounds(ac);
        if (ret == ASN1_PARSER_ERR) {
            ac->parser_status |= ASN1_STATUS_INVALID | ASN1_STATUS_OOB;
            return ASN1_PARSER_ERR;
        }

        raw_len = *ac->iter;
        if (raw_len == 0xFF && ac->iter == node->len.ptr + 1) {
            /* 8.1.3.5, 0xFF shall not be used */
            node->flags |= ASN1_BER_EVENT_INVALID_LEN;
            ac->parser_status = ASN1_STATUS_INVALID;
            return ASN1_PARSER_ERR;
        }

        if ((uint64_t) ((uint64_t)content_len +
            (uint64_t) ASN1_BER_GET_HIGH_TAG_NUM(raw_len)) > UINT32_MAX)
        {
            node->flags |= ASN1_BER_EVENT_LEN_TOO_LONG;
            ac->parser_status = ASN1_STATUS_INVALID;
            return ASN1_PARSER_ERR;
        }

        content_len += raw_len;
    }

    ac->iter++;

    node->len.len = content_len;
    return ASN1_PARSER_OK;
}


/**
 * \brief Check the content length and perform other inspections
 *        and decodings if necessary
 *
 * \param ac pointer to the ASN1 Context data
 *
 * \retval byte of the status of the parser
 */
uint8_t SCAsn1DecodeContent(Asn1Ctx *ac)
{

    Asn1Node *node = ASN1CTX_CUR_NODE(ac);

    /* Uops, if we are done, we break here */
    if (node->flags & ASN1_NODE_IS_EOC)
        return ASN1_PARSER_OK;

    /* First check the form of length (BER, DER, CER)
     * and if we are on a zero length */
    if (node->len.form != ASN1_BER_LEN_INDEFINITE &&
        node->len.len == 0)
    {
        node->data.len = 0;
        return ASN1_PARSER_OK;
    }

    node->data.ptr = ac->iter;
    /* If we have a complete length, check that
     * it is in bounds */
    if (ac->iter + node->len.len > ac->end) {
        /* We do not have all the content octets! */
        node->data.len = ac->end - ac->iter;
    } else {
        /* We have all the content octets */
        node->data.len = node->len.len;
    }

    return ASN1_PARSER_OK;
}

/**
 * \brief Decode and check the length, of the current node
 *        that we are parsing, also check invalid opts
 *
 * \param ac pointer to the ASN1 Context data
 *
 * \retval byte of the status of the parser
 */
uint8_t SCAsn1DecodeLength(Asn1Ctx *ac)
{
    uint8_t ret = 0;
    ret = SCAsn1CheckBounds(ac);
    if (ret == ASN1_PARSER_ERR) {
        ac->parser_status |= ASN1_STATUS_INVALID | ASN1_STATUS_OOB;
        return ASN1_PARSER_ERR;
    }

    Asn1Node *node = ASN1CTX_CUR_NODE(ac);
    /* Store the position */
    node->len.ptr = ac->iter;

    uint8_t len_byte = *ac->iter;

    //SCPrintByteBin(len_byte);

    if (*node->id.ptr == 0 && len_byte == 0) {
        node->flags |= ASN1_NODE_IS_EOC;
        ac->iter++;
        return ASN1_PARSER_OK;
    }

    if (ASN1_BER_IS_INDEFINITE_LEN(len_byte)) {
        node->len.form = ASN1_BER_LEN_INDEFINITE;
        node->len.len = 0;
        ac->iter++;

        uint8_t *tmp_iter = ac->iter;

        /* Check that e-o-c is in bounds */
        for (; tmp_iter < ac->end - 1; tmp_iter++) {
            if (ASN1_BER_IS_EOC(tmp_iter)) {
                node->data.len = tmp_iter - ac->iter;
                node->len.len = tmp_iter - ac->iter;
                return ASN1_PARSER_OK;
            }
        }

        /* EOC Not found */
        ac->parser_status |= ASN1_STATUS_INVALID;
        node->flags |= ASN1_BER_EVENT_EOC_NOT_FOUND;

        return ASN1_PARSER_ERR;

    } else {
        /* Look which form we get (and if it apply to the id type) */
        if (ASN1_BER_IS_SHORT_LEN(len_byte)) {
            node->len.form = ASN1_BER_LEN_SHORT;
            node->len.len = ASN1_BER_GET_SHORT_LEN(len_byte);
            ac->iter++;
        } else {
            node->len.form = ASN1_BER_LEN_LONG;

            /* Ok, let's parse the long form */
            return SCAsn1GetLengthLongForm(ac);
        }

    }
    return ASN1_PARSER_OK;
}

/**
 * \brief Decode and check the identifier information of the
 *        current node that we are parsing, also check invalid opts
 *
 * \param ac pointer to the ASN1 Context data
 *
 * \retval byte of the status of the parser
 */
uint8_t SCAsn1DecodeIdentifier(Asn1Ctx *ac)
{
    uint8_t ret = 0;
    ret = SCAsn1CheckBounds(ac);
    if (ret == ASN1_PARSER_ERR) {
        ac->parser_status |= ASN1_STATUS_INVALID | ASN1_STATUS_OOB;
        return ret;
    }

    Asn1Node *node = ASN1CTX_CUR_NODE(ac);
    /* Store the position */
    node->id.ptr = ac->iter;

    //SCPrintByteBin(*ac->iter);

    node->id.class_tag = ASN1_BER_GET_CLASS_TAG(*ac->iter);
    node->id.tag_type = ASN1_BER_IS_CONSTRUCTED(*ac->iter);

    if (ASN1_BER_IS_HIGH_TAG(*ac->iter)) {
        return SCAsn1GetHighTagNumber(ac);
    } else {
        node->id.tag_num = ASN1_BER_GET_LOW_TAG_NUM(*ac->iter);
        ac->iter++;
    }

    return ASN1_PARSER_OK;
}

/**
 * \brief Helper function that print the bits of a byte
 *        to check encoding internals
 * \param byte value of the byte
 */
void SCPrintByteBin(uint8_t byte)
{
    uint8_t i = 0;
    for (i = 8; i > 0; i--) {
        printf("%"PRIu8, (uint8_t)((byte >> (i - 1)) & 0x01));
        if (i == 5)
            printf(" ");
    }
    printf("\n");
}

/**
 * \brief check if we have remaining data available,
 *        otherwise the parser should stop
 * \param ac Asn1Ctx pointer initialized
 * \retval 1 if we are out of bounds, 0 if not
 */
uint8_t SCAsn1CheckBounds(Asn1Ctx *ac)
{
    return (ac->iter < ac->end && ac->iter >= ac->data)? ASN1_PARSER_OK : ASN1_PARSER_ERR;
}


/**
 * \brief Create a new ASN1 Parsing context
 *
 * \retval Asn1Ctx pointer to the new ctx
 */
Asn1Ctx *SCAsn1CtxNew(void)
{
    Asn1Ctx *ac = SCMalloc(sizeof(Asn1Ctx));

    if (unlikely(ac == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        return NULL;
    }
    memset(ac, 0, sizeof(Asn1Ctx));

    ac->asn1_stack = SCMalloc(sizeof(Asn1Node *) * asn1_max_frames_config);
    if (ac->asn1_stack == NULL) {
        SCFree(ac);
        return NULL;
    }
    memset(ac->asn1_stack, 0, sizeof(Asn1Node *) * asn1_max_frames_config);

    return ac;
}

/**
 * \brief Destroy an ASN1 Parsing context
 *
 * \param Asn1Ctx pointer to the new ctx
 */
void SCAsn1CtxDestroy(Asn1Ctx *ac)
{
    if (ac == NULL)
        return;

    for (uint16_t i = 0; i < asn1_max_frames_config; i++) {
        Asn1Node *node = ASN1CTX_GET_NODE(ac, i);
        if (node == NULL) {
            break;
        }
        SCFree(node);
    }

    SCFree(ac->asn1_stack);
    SCFree(ac);
}

/**
 * \brief Create a new node at the array stack of frames in the ctx
 *
 * \param ac pointer to the ASN1 ctx
 * \param node index of the frame that we are going to allocate
 *             at the asn1 stack in the parser
 *
 * \retval Asn1Node pointer to the new node allocated
 */
static Asn1Node *SCAsn1CtxNewFrame(Asn1Ctx *ac, uint16_t node)
{
    if (node >= asn1_max_frames_config) {
        return NULL;
    }

    if (ac->asn1_stack[node] == NULL)
        ac->asn1_stack[node] = SCMalloc(sizeof(Asn1Node));

    if (ac->asn1_stack[node] == NULL)
        return NULL;

    memset(ac->asn1_stack[node], 0, sizeof(Asn1Node));
    return ac->asn1_stack[node];
}

/**
 * \brief Initialize the data of the ASN1 parser ctx with the asn1 raw buffer
 *
 * \param ac pointer to the ASN1 ctx
 * \param data pointer to the data to process (binary raw of asn1)
 * \param length length of the asn1 raw buffer
 *
 * \retval void
 */
void SCAsn1CtxInit(Asn1Ctx *ac, uint8_t *data, uint16_t length)
{
    ac->data = data;
    ac->iter = data;
    ac->len = length;
    ac->end = data + length;
    ac->parser_status = ASN1_STATUS_OK;
}

/**
 * \brief Decode the nodes/frames located at certain position/level
 *
 * \param ac pointer to the ASN1 ctx
 * \param node_id node index at the asn1 stack of the ctx
 *
 * \retval byte of parser status
 */
uint8_t SCAsn1Decode(Asn1Ctx *ac, uint16_t node_id)
{
    Asn1Node *node = NULL;
    uint8_t ret = 0;

    /* while remaining data, and no fatal error, or end, or max stack frames */
    while (ac->iter < ac->end
           && !(ac->parser_status & ASN1_STATUS_DONE)
           && ac->cur_frame < asn1_max_frames_config)
    {
        /* Prepare a new frame */
        if (SCAsn1CtxNewFrame(ac, node_id) == NULL)
            break;

        ac->cur_frame = node_id;
        node = ASN1CTX_GET_NODE(ac, node_id);

        SCLogDebug("ASN1 Getting ID, cur:%x remaining %"PRIu32, (uint8_t)*ac->iter, (uint32_t)(ac->end - ac->iter));

        /* Get identifier/tag */
        ret = SCAsn1DecodeIdentifier(ac);
        if (ret == ASN1_PARSER_ERR) {
            SCLogDebug("Error parsing identifier");

            node->flags |= ASN1_BER_EVENT_INVALID_ID;
            ac->ctx_flags |= node->flags;

            break;
        }

        SCLogDebug("ASN1 Getting LEN");

        /* Get length of content */
        ret = SCAsn1DecodeLength(ac);
        if (ret == ASN1_PARSER_ERR) {
            SCLogDebug("Error parsing length");

            node->flags |= ASN1_BER_EVENT_INVALID_LEN;
            ac->ctx_flags |= node->flags;

            break;
        }

        if ( !(node->flags & ASN1_NODE_IS_EOC)) {
            SCLogDebug("ASN1 Getting CONTENT");

            /* Inspect content */
            ret = SCAsn1DecodeContent(ac);
            if (ret == ASN1_PARSER_ERR) {
                SCLogDebug("Error parsing content");

                break;
            }

            /* Skip to the next record (if any) */
            if (node->id.tag_type != ASN1_TAG_TYPE_CONSTRUCTED)
                /* Is primitive, skip it all (no need to decode it)*/
                ac->iter += node->data.len;
        }

        /* Check if we are done with data */
        ret = SCAsn1CheckBounds(ac);
        if (ret == ASN1_PARSER_ERR) {

            ac->parser_status |= ASN1_STATUS_DONE;
            /* There's no more data available */
            ret = ASN1_PARSER_OK;

            break;
        }
#if 0
        printf("Tag Num: %"PRIu32", Tag Type: %"PRIu8", Class:%"PRIu8", Length: %"PRIu32"\n", node->id.tag_num, node->id.tag_type, node->id.class_tag, node->len.len);
        printf("Data: \n");
        PrintRawDataFp(stdout, node->data.ptr, node->len.len);
        printf(" -- EOD --\n");
#endif

        /* Stack flags/events here, so we have the resume at the ctx flags */
        ac->ctx_flags |= node->flags;

        /* Check if it's not a primitive type,
         * then we need to decode contents */
        if (node->id.tag_type == ASN1_TAG_TYPE_CONSTRUCTED) {
            ret = SCAsn1Decode(ac, node_id + 1);
        } /* Else we have reached a primitive type and stop the recursion,
           * look if we have other branches at the same level */

        /* But first check if it's a constructed node, and the sum of child
         * lengths was more than the length of this frame
         * this would mean that we have an overflow at the attributes */
        if (ac->iter > node->data.ptr + node->data.len + 1) {
            /* We decoded more length on this frame */
        }

        node_id = ac->cur_frame + 1;
    }

    return ret;
}

/* ----------------------- Unit tests ------------------------ */
#ifdef UNITTESTS

/**
 * \test Check we handle extended identifiers correctly
 */
static int DecodeAsn1Test01(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 3;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->id.tag_num != 10) {
        ret = 0;
        printf("Error, expected tag_num 10, got %"PRIu32" :", node->id.tag_num);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle extended identifiers correctly
 */
static int DecodeAsn1Test02(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x81\x81\x81\x81\x06";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 6;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->id.tag_num != 10) {
        ret = 0;
        printf("Error, expected tag_num 10, got %"PRIu32": ", node->id.tag_num);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle short identifiers correctly
 */
static int DecodeAsn1Test03(void)
{
    uint8_t *str = (uint8_t *) "\x28";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 1;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->id.tag_num != 8) {
        ret = 0;
        printf("Error, expected tag_num 10, got %"PRIu32": ", node->id.tag_num);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle extended lengths correctly with indefinite form
 */
static int DecodeAsn1Test04(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06\x80\x12\x12\x12\x00\x00";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 9;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->len.len != 3) {
        ret = 0;
        printf("Error, expected length 3, got %"PRIu32": ", node->len.len);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle extended lengths correctly
 *       in the definite form
 */
static int DecodeAsn1Test05(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06\x82\x10\x10";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 6;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->len.len!= 32) {
        ret = 0;
        printf("Error, expected length 10, got %"PRIu32": ", node->len.len);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle short lengths correctly
 */
static int DecodeAsn1Test06(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06\x26";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 4;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->len.len != 38) {
        ret = 0;
        printf("Error, expected length 10, got %"PRIu32": ", node->len.len);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle events correctly
 */
static int DecodeAsn1Test07(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x00\x84\x06";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 4;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if ( !(ac->ctx_flags & ASN1_BER_EVENT_INVALID_ID)
        || !(node->flags & ASN1_BER_EVENT_INVALID_ID))
    {
        ret = 0;
        printf("Error, expected invalid id, got flags %"PRIu8": ", ac->ctx_flags);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle events correctly
 */
static int DecodeAsn1Test08(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06\x81\xFF";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 5;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if ( !(ac->ctx_flags & ASN1_BER_EVENT_INVALID_LEN)
        || !(node->flags & ASN1_BER_EVENT_INVALID_LEN))
    {
        ret = 0;
        printf("Error, expected invalid length, got flags %"PRIu8": ", ac->ctx_flags);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Check we handle events correctly
 */
static int DecodeAsn1Test09(void)
{
    uint8_t *str = (uint8_t *) "\x3F\x84\x06\x80\xAB\xCD\xEF";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = 7;

    SCAsn1CtxInit(ac, str, len);

    SCAsn1Decode(ac, ac->cur_frame);
    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if ( !(ac->ctx_flags & ASN1_BER_EVENT_EOC_NOT_FOUND)
        || !(node->flags & ASN1_BER_EVENT_EOC_NOT_FOUND))
    {
        ret = 0;
        printf("Error, expected eoc not found, got flags %"PRIu8": ", ac->ctx_flags);
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \test Decode a big chunk of data
 */
static int DecodeAsn1Test10(void)
{
    // Example from the specification X.690-0207 Appendix A.3
    uint8_t *str = (uint8_t *) "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;
    uint8_t ret = 1;

    uint16_t len = strlen((char *)str)-1;

    SCAsn1CtxInit(ac, str, len);

    ret = SCAsn1Decode(ac, ac->cur_frame);

    /* General checks */
    if (ret != ASN1_PARSER_OK) {
        printf("Error decoding asn1 data: ");
        ret = 0;
        goto end;
    }

    if (ac->cur_frame != 59) {
        printf("Error decoding asn1 data, not all the nodes"
               "were correctly decoded: ");
        ret = 0;
        goto end;
    }

    if (ac->iter != ac->end) {
        printf("Error decoding asn1 data, not all the nodes"
               "were correctly decoded: ");
        ret = 0;
        goto end;
    }

    Asn1Node *node = ASN1CTX_GET_NODE(ac, 0);
    if (node->len.len != 133) {
        printf("Error decoding asn1 data, not all the nodes"
               "were correctly decoded: ");
        ret = 0;
        goto end;
    }

    node = ASN1CTX_GET_NODE(ac, 30);
    if (node->len.len != 133) {
        printf("Error decoding asn1 data, not all the nodes"
               "were correctly decoded: ");
        ret = 0;
        goto end;
    }

end:
    SCAsn1CtxDestroy(ac);
    return ret;
}

#endif

void DecodeAsn1RegisterTests(void)
{
#ifdef UNITTESTS
     UtRegisterTest("DecodeAsn1Test01", DecodeAsn1Test01);
     UtRegisterTest("DecodeAsn1Test02", DecodeAsn1Test02);
     UtRegisterTest("DecodeAsn1Test03", DecodeAsn1Test03);

     UtRegisterTest("DecodeAsn1Test04", DecodeAsn1Test04);
     UtRegisterTest("DecodeAsn1Test05", DecodeAsn1Test05);
     UtRegisterTest("DecodeAsn1Test06", DecodeAsn1Test06);

     UtRegisterTest("DecodeAsn1Test07", DecodeAsn1Test07);
     UtRegisterTest("DecodeAsn1Test08", DecodeAsn1Test08);
     UtRegisterTest("DecodeAsn1Test09", DecodeAsn1Test09);

     UtRegisterTest("DecodeAsn1Test10", DecodeAsn1Test10);
#endif
}

