/* Copyright (C) 2015-2022 Open Information Security Foundation
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

/** \file
 *
 *  \author Kevin Wong <kwong@solananetworks.com>
 *
 *  Based on detect-engine-modbus.c
 */

#include "suricata-common.h"

#include "app-layer.h"
#include "app-layer-enip-common.h"

#include "detect.h"
#include "detect-cipservice.h"
#include "detect-engine-enip.h"

#include "flow.h"

#include "util-debug.h"

#if 0
/**
 * \brief Print fields from ENIP Packet
 * @param enip_data
 */
void PrintENIPAL(ENIPTransaction *enip_data)
{
    SCLogDebug("============================================");
    SCLogDebug("ENCAP HEADER cmd 0x%x, length %d, session 0x%x, status 0x%x",
            enip_data->header.command, enip_data->header.length,
            enip_data->header.session, enip_data->header.status);
    //SCLogDebug("context 0x%x option 0x%x", enip_data->header.context, enip_data->header.option);
    SCLogDebug("ENCAP DATA HEADER handle 0x%x, timeout %d, count %d",
            enip_data->encap_data_header.interface_handle,
            enip_data->encap_data_header.timeout,
            enip_data->encap_data_header.item_count);
    SCLogDebug("ENCAP ADDR ITEM type 0x%x, length %d",
            enip_data->encap_addr_item.type, enip_data->encap_addr_item.length);
    SCLogDebug("ENCAP DATA ITEM type 0x%x, length %d sequence 0x%x",
            enip_data->encap_data_item.type, enip_data->encap_data_item.length,
            enip_data->encap_data_item.sequence_count);

    CIPServiceEntry *svc = NULL;

    int count = 0;
    TAILQ_FOREACH(svc, &enip_data->service_list, next)
    {
        //SCLogDebug("CIP Service #%d : 0x%x", count, svc->service);
        count++;
    }
}
#endif

/**
 * \brief Matches the rule to the CIP segment in ENIP Packet
 * @param svc - the CIP service entry
 * * @param cipserviced - the CIP service rule
 */
static int CIPPathMatch(CIPServiceEntry *svc, DetectCipServiceData *cipserviced)
{
    uint16_t class = 0;
    uint16_t attrib = 0;
    int found_class = 0;

    SegmentEntry *seg = NULL;
    TAILQ_FOREACH(seg, &svc->segment_list, next)
    {
        switch(seg->segment)
        {
            case PATH_CLASS_8BIT:
                class = seg->value;
                if (cipserviced->cipclass == class)
                {
                    if (cipserviced->tokens == 2)
                    {// if rule only has class
                        return 1;
                    } else
                    {
                        found_class = 1;
                    }
                }
                break;
            case PATH_INSTANCE_8BIT:
                break;
            case PATH_ATTR_8BIT: //single attribute
                attrib = seg->value;
                if ((cipserviced->tokens == 3) &&
                        (cipserviced->cipclass == class) &&
                        (cipserviced->cipattribute == attrib) &&
                        (cipserviced->matchattribute == 1))
                { // if rule has class & attribute, matched all here
                    return 1;
                }
                if ((cipserviced->tokens == 3) &&
                        (cipserviced->cipclass == class) &&
                        (cipserviced->matchattribute == 0))
                { // for negation rule on attribute
                    return 1;
                }
                break;
            case PATH_CLASS_16BIT:
                class = seg->value;
                if (cipserviced->cipclass == class)
                {
                    if (cipserviced->tokens == 2)
                    {// if rule only has class
                        return 1;
                    } else
                    {
                        found_class = 1;
                    }
                }
                break;
            case PATH_INSTANCE_16BIT:
                break;
            default:
                return 0;
        }
    }

    if (found_class == 0)
    { // if haven't matched class yet, no need to check attribute
        return 0;
    }

    if ((svc->service == CIP_SET_ATTR_LIST) ||
            (svc->service == CIP_GET_ATTR_LIST))
    {
        AttributeEntry *attr = NULL;
        TAILQ_FOREACH    (attr, &svc->attrib_list, next)
        {
            if (cipserviced->cipattribute == attr->attribute)
            {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * \brief Matches the rule to the ENIP Transaction
 * @param enip_data - the ENIP transaction
 * * @param cipserviced - the CIP service rule
 */

static int CIPServiceMatch(ENIPTransaction *enip_data,
        DetectCipServiceData *cipserviced)
{
    int count = 1;
    CIPServiceEntry *svc = NULL;
    //SCLogDebug("CIPServiceMatchAL");
    TAILQ_FOREACH(svc, &enip_data->service_list, next)
    {
        SCLogDebug("CIPServiceMatchAL service #%d : 0x%x dir %d",
                count, svc->service,  svc->direction);

        if (cipserviced->cipservice == svc->service)
        { // compare service
            //SCLogDebug("Rule Match for cip service %d",cipserviced->cipservice );

            if (cipserviced->tokens > 1)
            { //if rule params have class and attribute


                if ((svc->service == CIP_SET_ATTR_LIST) || (svc->service
                                == CIP_SET_ATTR_SINGLE) || (svc->service
                                == CIP_GET_ATTR_LIST) || (svc->service
                                == CIP_GET_ATTR_SINGLE))
                { //decode path
                    if (CIPPathMatch(svc, cipserviced) == 1)
                    {
                        if (svc->direction == 1) return 0; //don't match responses

                        return 1;
                    }
                }
            } else
            {
                if (svc->direction == 1) return 0; //don't match responses

                // SCLogDebug("CIPServiceMatchAL found");
                return 1;
            }
        }
        count++;
    }
    return 0;
}

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect ( and sm: SigMatch to inspect)
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param alstate  App layer state
 *  \param txv      Pointer to ENIP Transaction structure
 *
 *  \retval 0 no match or 1 match
 */
uint8_t DetectEngineInspectCIP(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();


    ENIPTransaction *tx = (ENIPTransaction *) txv;
    DetectCipServiceData *cipserviced = (DetectCipServiceData *)engine->smd->ctx;

    if (cipserviced == NULL)
    {
        SCLogDebug("no cipservice state, no match");
        SCReturnInt(0);
    }
    //SCLogDebug("DetectEngineInspectCIP %d", cipserviced->cipservice);

    if (CIPServiceMatch(tx, cipserviced) == 1)
    {
        //SCLogDebug("DetectCIPServiceMatchAL found");
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect ( and sm: SigMatch to inspect)
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param alstate  App layer state
 *  \param txv      Pointer to ENIP Transaction structure
 *
 *  \retval 0 no match or 1 match
 */

uint8_t DetectEngineInspectENIP(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();

    ENIPTransaction *tx = (ENIPTransaction *) txv;
    DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *)engine->smd->ctx;

    if (enipcmdd == NULL)
    {
        SCLogDebug("no enipcommand state, no match");
        SCReturnInt(0);
    }

    //SCLogDebug("DetectEngineInspectENIP %d, %d", enipcmdd->enipcommand, tx->header.command);

    if (enipcmdd->enipcommand == tx->header.command)
    {
        // SCLogDebug("DetectENIPCommandMatchAL found!");
        SCReturnInt(1);
    }

    SCReturnInt(0);
}
