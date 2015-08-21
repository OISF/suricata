/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * Set up ENIP Commnad and CIP Service rule parsing and entry point for matching
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"

#include "detect-cipservice.h"
//#include "detect-engine-enip.h"
//#include "decode-enip.h"

#include "app-layer-enip-common.h"


/**
 * \brief Extract 8 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint8(uint8_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    *res = *(input + *offset);
    *offset += sizeof(uint8_t);
    SCReturn;
}

/**
 * \brief Extract 16 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint16(uint16_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint16(res, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint16_t);
    SCReturn;
}

/**
 * \brief Extract 32 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint32(uint32_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint32(res, BYTE_LITTLE_ENDIAN, sizeof(uint32_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint32_t);
    SCReturn;
}

/**
 * \brief Extract 64 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint64(uint64_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint64(res, BYTE_LITTLE_ENDIAN, sizeof(uint64_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint64_t);
    SCReturn;
}

/**
 * \brief Create node in list of CIP Service data link list
 * @param enip_data
 * @return
 */
CIPServiceData *CreateCIPServiceData(ENIPData *enip_data)
{

    CIPServiceData *node = malloc(sizeof(CIPServiceData));
    memset(node, 0, sizeof(CIPServiceData));
    node->next = 0;

    if (enip_data->service_head == NULL)
    {//init first node
        enip_data->service_head = node;
    } else
    {
        enip_data->service_tail->next = node; //connect tail to new node
    }
    enip_data->service_tail = node; //set new tail

    return node;
}

/**
 * \brief Free memory for CIP Service link list
 * @param cip_data
 */
void FreeCIPServiceData(CIPServiceData *cip_data)
{
    if (cip_data == NULL)
        return;

    CIPServiceData *next = cip_data->next;
    free(cip_data);
    if (next != NULL)
    {
        FreeCIPServiceData(next);
    }
}

/*
 *
 ************************************************************ CIP SERVICE CODE ********************************************************************
 *
 */

/**
 * \brief Match CIP Service data against rule
 * @param p
 * @param enip_data
 * @param cipserviced
 * @return
 */
/*
int CIPServiceMatch(Packet *p, ENIPData *enip_data,
        DetectCipServiceData *cipserviced)
{

    int count = 1;
    CIPServiceData *temp = enip_data->service_head;
    while (temp != NULL)
    {
        //SCLogDebug("CIP Service #%d : 0x%x\n", count, temp->service);
        if (cipserviced->cipservice == temp->service)
        { // compare service
            //SCLogDebug("Rule Match for cip service %d\n",cipserviced->cipservice );
            if (cipserviced->tokens > 1)
            { //if rule params have class and attribute
                if ((temp->service == CIP_SET_ATTR_LIST) || (temp->service
                        == CIP_SET_ATTR_SINGLE) || (temp->service
                        == CIP_GET_ATTR_LIST) || (temp->service
                        == CIP_GET_ATTR_SINGLE))
                { //decode path
                    if (DecodeCIPRequestPath(p, temp,
                            temp->request.path_offset, cipserviced) == 1)
                    {
                        return 1;
                    }
                }
            } else
            {
                return 1;
            }
        }
        count++;
        temp = temp->next;
    }
    return 0;
}

*/

/**
 * \brief Print fields from ENIP Packet
 * @param enip_data
 */
void PrintENIP(ENIPData *enip_data)
{
    printf("============================================\n");
    printf("ENCAP HEADER cmd 0x%x, length %d, session 0x%x, status 0x%x\n",
            enip_data->header.command, enip_data->header.length,
            enip_data->header.session, enip_data->header.status);
    //printf("context 0x%x option 0x%x\n", enip_data->header.context, enip_data->header.option);
    printf("ENCAP DATA HEADER handle 0x%x, timeout %d, count %d\n",
            enip_data->encap_data_header.interface_handle,
            enip_data->encap_data_header.timeout,
            enip_data->encap_data_header.item_count);
    printf("ENCAP ADDR ITEM type 0x%x, length %d \n",
            enip_data->encap_addr_item.type, enip_data->encap_addr_item.length);
    printf("ENCAP DATA ITEM type 0x%x, length %d sequence 0x%x\n",
            enip_data->encap_data_item.type, enip_data->encap_data_item.length,
            enip_data->encap_data_item.sequence_count);

    int count = 1;
    CIPServiceData *temp = enip_data->service_head;
    while (temp != NULL)
    {
        printf("CIP Service #%d : 0x%x\n", count, temp->service);
        count++;
        temp = temp->next;
    }
}



int CIPPathMatchAL(CIPServiceEntry *svc, DetectCipServiceData *cipserviced)
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
                if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                                == class) && (cipserviced->cipattribute == attrib) && (cipserviced->matchattribute == 1))
                { // if rule has class & attribute, matched all here
                    return 1;
                }
                if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                                == class) && (cipserviced->matchattribute == 0))
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
                SCLogDebug(
                        "CIPPathMatchAL: UNKNOWN SEGMENT 0x%x service 0x%x\n",
                        segment, node->service);
                return 0;
        }
    }
      
    if (found_class == 0)
    { // if haven't matched class yet, no need to check attribute
        return 0;
    }

    if ((svc->service == CIP_SET_ATTR_LIST) || (svc->service == CIP_GET_ATTR_LIST))
    {
        AttributeEntry *attr = NULL;
        TAILQ_FOREACH(attr, &svc->attrib_list, next)
        {
            if (cipserviced->cipattribute == attr->attribute)
            {
                return 1;
            }
        }
    }
    
    return 0;
}



int CIPServiceMatchAL(ENIPTransaction *enip_data, DetectCipServiceData *cipserviced)
{

    int count = 1;
    CIPServiceEntry *svc = NULL; 
    //printf("CIPServiceMatchAL\n");
    TAILQ_FOREACH(svc, &enip_data->service_list, next) {    
        //printf("CIPServiceMatchAL service #%d : 0x%x\n", count, svc->service);
        if (cipserviced->cipservice == svc->service)
        { // compare service
            //SCLogDebug("Rule Match for cip service %d\n",cipserviced->cipservice );
            if (cipserviced->tokens > 1)
            { //if rule params have class and attribute
                

                if ((svc->service == CIP_SET_ATTR_LIST) || (svc->service
                        == CIP_SET_ATTR_SINGLE) || (svc->service
                        == CIP_GET_ATTR_LIST) || (svc->service
                        == CIP_GET_ATTR_SINGLE))
                { //decode path
                    if (CIPPathMatchAL(svc, cipserviced) == 1)
                    {
                        return 1;
                    }
                }                
            } else
            {
                printf("CIPServiceMatchAL found\n");
                return 1;
            }
        }
        count++;
    }
    return 0;
}


/**
 * \brief Print fields from ENIP Packet
 * @param enip_data
 */
void PrintENIPAL(ENIPTransaction *enip_data)
{
    printf("============================================\n");
    printf("ENCAP HEADER cmd 0x%x, length %d, session 0x%x, status 0x%x\n",
            enip_data->header.command, enip_data->header.length,
            enip_data->header.session, enip_data->header.status);
    //printf("context 0x%x option 0x%x\n", enip_data->header.context, enip_data->header.option);
    printf("ENCAP DATA HEADER handle 0x%x, timeout %d, count %d\n",
            enip_data->encap_data_header.interface_handle,
            enip_data->encap_data_header.timeout,
            enip_data->encap_data_header.item_count);
    printf("ENCAP ADDR ITEM type 0x%x, length %d \n",
            enip_data->encap_addr_item.type, enip_data->encap_addr_item.length);
    printf("ENCAP DATA ITEM type 0x%x, length %d sequence 0x%x\n",
            enip_data->encap_data_item.type, enip_data->encap_data_item.length,
            enip_data->encap_data_item.sequence_count);

    CIPServiceEntry *svc = NULL;      
 
    int count = 0;
    TAILQ_FOREACH(svc, &enip_data->service_list, next) {
        printf("CIP Service #%d : 0x%x\n", count, svc->service);
        count++;
    }
}


/**
 * \brief CIP Service Detect Prototypes
 */
//int DetectCipServiceMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
//        Signature *, const SigMatchCtx *);
static int DetectCipServiceSetup(DetectEngineCtx *, Signature *, char *);
static void DetectCipServiceFree(void *);
static void DetectCipServiceRegisterTests(void);

int DetectCIPServiceMatchAL (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);

/**
 * \brief Registration function for cip_service: keyword
 */
void DetectCipServiceRegister(void)
{
    SCEnter();
    sigmatch_table[DETECT_CIPSERVICE].name = "cip_service"; //rule keyword
    sigmatch_table[DETECT_CIPSERVICE].desc = "Rules for detecting CIP Service ";
    sigmatch_table[DETECT_CIPSERVICE].url = "www.solananetworks.com";
   // sigmatch_table[DETECT_CIPSERVICE].Match = DetectCipServiceMatch;
    sigmatch_table[DETECT_CIPSERVICE].Match = NULL;
    sigmatch_table[DETECT_CIPSERVICE].AppLayerMatch = DetectCIPServiceMatchAL; //DetectEngineInspectENIP;
    sigmatch_table[DETECT_CIPSERVICE].alproto = ALPROTO_ENIP;
    sigmatch_table[DETECT_CIPSERVICE].Setup = DetectCipServiceSetup;
    sigmatch_table[DETECT_CIPSERVICE].Free = DetectCipServiceFree;
    sigmatch_table[DETECT_CIPSERVICE].RegisterTests
            = DetectCipServiceRegisterTests;

    SCReturn;

}


int DetectCIPServiceMatchAL (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectCipServiceData *cipserviced = (DetectCipServiceData *)m->ctx;
    ENIPState *enip_state = (ENIPState *)state;
    int ret = 0;
     
    if (enip_state == NULL) {
        printf("no cipservice state, no match\n");
        SCReturnInt(0);
    }

    printf("DetectCIPServiceMatchAL cipservice %d\n", cipserviced->cipservice);
//    printf("DetectCIPServiceMatch2 tx %d\n", enip_state->transaction_max);

    
    
    ENIPTransaction *tx = NULL;
    int  count = 0;
    TAILQ_FOREACH(tx, &enip_state->tx_list, next) {
   //   printf("DetectCIPServiceMatch2 transaction #%d\n", count);
      //PrintENIPAL(tx);
      if (CIPServiceMatchAL(tx, cipserviced) == 1){
          SCLogDebug("DetectCIPServiceMatchAL found\n");
          return 1;
      }
      count++;
    }
   
    SCReturnInt(ret);
}



/**
 * \brief This function is used to match cip_service rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectCipServiceData
 *
 * \retval 0 no match
 * \retval 1 match
 */

int DetectCipServiceMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectCipServiceData *cipserviced = (DetectCipServiceData *) ctx;

    if (PKT_IS_PSEUDOPKT(p))
    {
        SCLogDebug("Packet is fake");
    }

    if (PKT_IS_IPV4(p))
    {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p))
    {
        SCLogDebug("Packet is IPv6");
        return ret;
    } else
    {
        SCLogDebug("Packet is not IPv4 or IPv6");
        return ret;
    }

    ENIPData enip_data;
    enip_data.service_head = NULL; //initialize pointer
    enip_data.service_tail = NULL;

    //	SCLogDebug("payload total length %d\n", p->payload_len);

    //basic port check
    if ((p->sp == ENIP_PORT) || (p->dp == ENIP_PORT))
    {
        if (p->dp == ENIP_PORT)
            enip_data.direction = 0;
        else
            enip_data.direction = 1;
    } else
    {
        return 0;
    }
/*
    int status = DecodeENIP(p, &enip_data); //perform EtherNet/IP decoding

    if (status != 0)
    {
        //PrintENIP(&enip_data); //print gathered ENIP data
       // ret = CIPServiceMatch(p, &enip_data, cipserviced); //check if rule matches
    }
*/
    FreeCIPServiceData(enip_data.service_head); //free CIP service data

    return ret;
}

/**
 * \brief This function is used to parse cip_service options passed via cip_service: keyword
 *
 * \param rulestr Pointer to the user provided rulestr options
 * Takes comma seperated string with numeric tokens.  Only first 3 are used
 *
 * \retval cipserviced pointer to DetectCipServiceData on success
 * \retval NULL on failure
 */
DetectCipServiceData *DetectCipServiceParse(char *rulestr)
{
    const char delims[] = ",";
    DetectCipServiceData *cipserviced = NULL;

    //SCLogDebug("DetectCipServiceParse - rule string  %s\n", rulestr);

    cipserviced = SCMalloc(sizeof(DetectCipServiceData));

    cipserviced->cipservice = 0;
    cipserviced->cipclass = 0;
    cipserviced->matchattribute = 1;
    cipserviced->cipattribute = 0;

    if (unlikely(cipserviced == NULL))
        goto error;

    char* token;
    char *save;
    int var;
    int input[3];
    int i = 0;

    token = strtok_r(rulestr, delims, &save);
    while (token != NULL)
    {
        if (i > 2) //for now only need 3 parameters
        {
            printf("DetectEnipCommandParse: Too many parameters\n");
            goto error;
        }

        if (i < 2) //if on service or class
        {
            if (!isdigit((int) *token))
            {
                printf("DetectCipServiceParse - Parameter Error %s\n", token);
                goto error;
            }
        } else //if on attribute
        {

            if (token[0] == '!')
            {
                cipserviced->matchattribute = 0;
                token++;
            }

            if (!isdigit((int) *token))
            {
                printf("DetectCipServiceParse - Attribute Error  %s\n", token);
                goto error;
            }

        }

        unsigned long num = atol(token);
        if ((num > MAX_CIP_SERVICE) && (i == 0))//if service greater than 7 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP service %lu\n", num);
            goto error;
        } else if ((num > MAX_CIP_CLASS) && (i == 1))//if service greater than 16 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP class %lu\n", num);
            goto error;
        } else if ((num > MAX_CIP_ATTRIBUTE) && (i == 2))//if service greater than 16 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP attribute %lu\n", num);
            goto error;
        }

        sscanf(token, "%d", &var);
        input[i++] = var;

        token = strtok_r(NULL, delims, &save);
    }

    cipserviced->cipservice = input[0];
    cipserviced->cipclass = input[1];
    cipserviced->cipattribute = input[2];
    cipserviced->tokens = i;

    SCLogDebug("DetectCipServiceParse - tokens %d\n", cipserviced->tokens);
    SCLogDebug("DetectCipServiceParse - service %d\n", cipserviced->cipservice);
    SCLogDebug("DetectCipServiceParse - class %d\n", cipserviced->cipclass);
    SCLogDebug("DetectCipServiceParse - match attribute %d\n",
                cipserviced->matchattribute);
    SCLogDebug("DetectCipServiceParse - attribute %d\n",
            cipserviced->cipattribute);

    //return cipserviced;
    SCReturnPtr(cipserviced, "DetectENIPFunction");

    error: if (cipserviced)
        SCFree(cipserviced);
    printf("DetectCipServiceParse - Error Parsing Parameters\n");
    //return NULL;
    SCReturnPtr(NULL, "DetectENIP");
}

/**
 * \brief this function is used to a cipserviced the parsed cip_service data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided cip_service options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCipServiceSetup(DetectEngineCtx *de_ctx, Signature *s,
        char *rulestr)
{
    SCEnter();

    DetectCipServiceData *cipserviced = NULL;
    SigMatch *sm = NULL;


    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_ENIP) {
          SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
          goto error;
      }


    cipserviced = DetectCipServiceParse(rulestr);
    if (cipserviced == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CIPSERVICE;
    sm->ctx = (void *) cipserviced;

  //  SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
  //  s->flags |= SIG_FLAG_REQUIRE_PACKET;
  //  SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_ENIP_MATCH);
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
   // s->alproto = ALPROTO_ENIP;
   // s->flags |= SIG_FLAG_APPLAYER;

    SCReturnInt(0);

    error: if (cipserviced != NULL)
        DetectCipServiceFree(cipserviced);
    if (sm != NULL)
        SCFree(sm);
    printf("DetectCipServiceSetup - Error\n");

    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectCipServiceData
 *
 * \param ptr pointer to DetectCipServiceData
 */
void DetectCipServiceFree(void *ptr)
{
    DetectCipServiceData *cipserviced = (DetectCipServiceData *) ptr;
    SCFree(cipserviced);
}

#ifdef UNITTESTS

/**
 * \test Test CIP Command parameter parsing
 */
static int DetectCipServiceParseTest01 (void)
{

    uint8_t res = 1;

    /*DetectCipServiceData *cipserviced = NULL;
     cipserviced = DetectCipServiceParse("1");
     if (cipserviced != NULL)
     {
     if (cipserviced->cipservice == 1)
     {
     res = 1;
     }

     DetectCipServiceFree(cipserviced);
     }
     */
    return res;
}

/**
 * \test Test CIP Service signature
 */
static int DetectCipServiceSignatureTest01 (void)
{
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
    goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (cip_service:1; sid:1; rev:1;)");
    if (sig == NULL)
    {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
    end:
    if (de_ctx != NULL)
    DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectCipService
 */
void DetectCipServiceRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectCipServiceParseTest01",
            DetectCipServiceParseTest01, 1);
    UtRegisterTest("DetectCipServiceSignatureTest01",
            DetectCipServiceSignatureTest01, 1);
#endif /* UNITTESTS */
}

/*
 *
 ************************************************************ ENIP COMMAND CODE ********************************************************************
 *
 */

/**
 * \brief ENIP Commond Detect Prototypes
 */
//int DetectEnipCommandMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
//        Signature *, const SigMatchCtx *);
static int DetectEnipCommandSetup(DetectEngineCtx *, Signature *, char *);
static void DetectEnipCommandFree(void *);
static void DetectEnipCommandRegisterTests(void);

int DetectENIPCommandMatchAL (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);

/**
 * \brief Registration function for enip_command: keyword
 */
void DetectEnipCommandRegister(void)
{
    sigmatch_table[DETECT_ENIPCOMMAND].name = "enip_command"; //rule keyword
    sigmatch_table[DETECT_ENIPCOMMAND].desc
            = "Rules for detecting EtherNet/IP command";
    sigmatch_table[DETECT_ENIPCOMMAND].url = "www.solananetworks.com";
 //   sigmatch_table[DETECT_ENIPCOMMAND].Match = DetectEnipCommandMatch;
    sigmatch_table[DETECT_ENIPCOMMAND].Match = NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].AppLayerMatch = DetectENIPCommandMatchAL;// NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].alproto = ALPROTO_ENIP;
    sigmatch_table[DETECT_ENIPCOMMAND].Setup = DetectEnipCommandSetup;
    sigmatch_table[DETECT_ENIPCOMMAND].Free = DetectEnipCommandFree;
    sigmatch_table[DETECT_ENIPCOMMAND].RegisterTests
            = DetectEnipCommandRegisterTests;

}




int DetectENIPCommandMatchAL (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *)m->ctx;
    ENIPState *enip_state = (ENIPState *)state;
    int ret = 0; 
    
  //  printf("DetectENIPCommandMatch2\n");
    if (enip_state == NULL) {
        printf("no enip state, no match\n");
        SCReturnInt(0);
    }

  //  printf("DetectENIPCommandMatchAL enipcommand %d\n", enipcmdd->enipcommand);  
  //  printf("DetectENIPCommandMatchAL tx %d\n", enip_state->transaction_max);
   
    
    ENIPTransaction *tx = NULL;
    int  count = 0;
    TAILQ_FOREACH(tx, &enip_state->tx_list, next) {
      //PrintENIPAL(tx);
      //printf("DetectENIPCommandMatchAL transaction #%d, command %d\n", count, tx->header.command);
      if (enipcmdd->enipcommand == tx->header.command){
          SCLogDebug("DetectENIPCommandMatchAL found!\n");
          return 1;
      }     
      count++;
    }
         
    SCReturnInt(ret);    
}


/**
 * \brief This function is used to match cip_service rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectCipServiceData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectEnipCommandMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *) ctx;

    if (PKT_IS_PSEUDOPKT(p))
    {
        SCLogDebug("Packet is fake");
    }

    if (PKT_IS_IPV4(p))
    {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p))
    {
        SCLogDebug("Packet is IPv6");
        return ret;
    } else
    {
        SCLogDebug("Packet is not IPv4 or IPv6");
        return ret;
    }

    ENIPData enip_data;
    enip_data.service_head = NULL; //initialize pointer
    enip_data.service_tail = NULL;

    //basic port check
    if ((p->sp == ENIP_PORT) || (p->dp == ENIP_PORT))
    {
        if (p->dp == ENIP_PORT)
            enip_data.direction = 0;
        else
            enip_data.direction = 1;
    } else
    {
        return 0;
    }

    //    SCLogDebug("CIPSERVICE %d\n",enipcmdd->enipcommand);
/*
    int status = DecodeENIP(p, &enip_data); //perform EtherNet/IP decoding
    //PrintENIP(&enip_data); //print gathered ENIP data
    if (status > 0)
    {
        if (enipcmdd->enipcommand == enip_data.header.command) //check if rule matches
        {
            ret = 1;
        }
    }
*/
    FreeCIPServiceData(enip_data.service_head); //free CIP service data

    return ret;
}

/**
 * \brief This function is used to parse cip_service options passed via enip_command: keyword
 *
 * \param rulestr Pointer to the user provided rulestr options
 * Takes single single numeric value
 *
 * \retval enipcmdd pointer to DetectCipServiceData on success
 * \retval NULL on failure
 */

DetectEnipCommandData *DetectEnipCommandParse(char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;

    enipcmdd = SCMalloc(sizeof(DetectEnipCommandData));
    if (isdigit((int) *rulestr))
    {
        unsigned long cmd = atol(rulestr);
        if (cmd > MAX_ENIP_CMD) //if command greater than 16 bit
        {
            printf("DetectEnipCommandParse: Invalid ENIP command %lu\n", cmd);
            goto error;
        }

        enipcmdd->enipcommand = (uint16_t) atoi(rulestr);

    } else
    {
        goto error;
    }

    if (unlikely(enipcmdd == NULL))
        goto error;

    return enipcmdd;

    error: if (enipcmdd)
        SCFree(enipcmdd);
    printf("DetectEnipCommandParse - Error Parsing Parameters\n");
    return NULL;
}

/**
 * \brief this function is used by enipcmdd to parse enip_command data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip command options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipCommandSetup(DetectEngineCtx *de_ctx, Signature *s,
        char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;
    SigMatch *sm = NULL;


    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_ENIP) {
           SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
           goto error;
    }

    enipcmdd = DetectEnipCommandParse(rulestr);
    if (enipcmdd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ENIPCOMMAND;
    sm->ctx = (void *) enipcmdd;

    //SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    //s->flags |= SIG_FLAG_REQUIRE_PACKET;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    SCReturnInt(0);

    error: if (enipcmdd != NULL)
        DetectEnipCommandFree(enipcmdd);
    if (sm != NULL)
        SCFree(sm);
    printf("DetectEnipCommandSetup - Error\n");
    SCReturnInt(-1);

}

/**
 * \brief this function will free memory associated with DetectEnipCommandData
 *
 * \param ptr pointer to DetectEnipCommandData
 */
void DetectEnipCommandFree(void *ptr)
{
    DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *) ptr;
    SCFree(enipcmdd);
}

#ifdef UNITTESTS

/**
 * \test ENIP parameter test
 */

static int DetectEnipCommandParseTest01 (void)
{
    DetectEnipCommandData *enipcmdd = NULL;
    uint8_t res = 0;

    enipcmdd = DetectEnipCommandParse("1");
    if (enipcmdd != NULL)
    {
        if (enipcmdd->enipcommand == 1)
        {
            res = 1;
        }

        DetectEnipCommandFree(enipcmdd);
    }

    return res;
}

/**
 * \test ENIP Command signature test
 */
static int DetectEnipCommandSignatureTest01 (void)
{
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
    goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (enip_command:1; sid:1; rev:1;)");
    if (sig == NULL)
    {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
    end:
    if (de_ctx != NULL)
    DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectEnipCommand
 */
void DetectEnipCommandRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectEnipCommandParseTest01",
            DetectEnipCommandParseTest01, 1);
    UtRegisterTest("DetectEnipCommandSignatureTest01",
            DetectEnipCommandSignatureTest01, 1);
#endif /* UNITTESTS */
}

