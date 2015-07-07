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
 * Set up CIP Service rule parsing and entry point for matching1
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"

#include "detect-cipservice.h"
#include "decode-enip.h"


/**
 * Read 8 bits and push offset
 */
void ENIPExtractUint8(uint8_t *res, uint8_t *input, uint16_t *offset)
{
	SCEnter();
	*res = *(input + *offset);
	*offset += sizeof(uint8_t);
	SCReturn;
}

/**
 * Read 16 bits and push offset
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
 * Read 32 bits and push offset
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
 * Read 64 bits and push offset
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
 * Create cip service structures for storage
 */
CIP_SERVICE_DATA *CreateCIPServiceData(ENIP_DATA *enip_data)
{

	CIP_SERVICE_DATA *node = malloc(sizeof(CIP_SERVICE_DATA));
	memset(node, 0, sizeof(CIP_SERVICE_DATA));
	node->next = 0;

	if (enip_data->service_head == NULL)
	{//init first node
		enip_data->service_head = node;
	} else {
		enip_data->service_tail->next = node; //connect tail to new node
	}
	enip_data->service_tail = node; //set new tail

	return node;
}

/**
 * Free CIP Service data
 */
void FreeCIPServiceData(CIP_SERVICE_DATA *cip_data)
{
	if (cip_data == NULL)
		return;

	CIP_SERVICE_DATA *next = cip_data->next;
	free(cip_data);
	if (next != NULL) {
		FreeCIPServiceData(next);
	}
}




/*
 *
 ************************************************************ CIP SERVICE CODE ********************************************************************
 *
*/



/**
 * Check if ENIP data matches CIP Service rule
 * return 1 for match, 0 for fail
 */
int CIPServiceMatch(Packet *p, ENIP_DATA *enip_data, DetectCipServiceData *cipserviced)
{

	int count = 1;
	CIP_SERVICE_DATA *temp = enip_data->service_head;
	while (temp != NULL)
	{
		//SCLogDebug("CIP Service #%d : 0x%x\n", count, temp->service);
		if (cipserviced->cipservice == temp->service) { // compare service
			//SCLogDebug("Rule Match for cip service %d\n",cipserviced->cipservice );
			if (cipserviced->tokens > 1){ //if rule params have class and attribute
				if ( (temp->service == CIP_SET_ATTR_LIST) || (temp->service == CIP_SET_ATTR_SINGLE) || (temp->service == CIP_GET_ATTR_LIST) || (temp->service == CIP_GET_ATTR_SINGLE)  ){ //decode path
					if (DecodeCIPRequestPath(p, temp, temp->request.path_offset, cipserviced) == 1){
						return 1;
					}
				}
			}else {
				return 1;
			}
		}
		count++;
		temp = temp->next;
	}
	return 0;
}


/**
 * Print ENIP data
 */
void PrintENIP(ENIP_DATA *enip_data)
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
	CIP_SERVICE_DATA *temp = enip_data->service_head;
		while (temp != NULL)
		{
			printf("CIP Service #%d : 0x%x\n", count, temp->service);
			count++;
			temp = temp->next;
		}
}




/**
 * Rule Function Prototypes
 */
static int DetectCipServiceMatch(ThreadVars *, DetectEngineThreadCtx *,
		Packet *, Signature *, SigMatch *);
static int DetectCipServiceSetup(DetectEngineCtx *, Signature *, char *);
static void DetectCipServiceFree(void *);
static void DetectCipServiceRegisterTests(void);

/**
 * \brief Registration function for cip_service: keyword
 */
void DetectCipServiceRegister(void)
{
	sigmatch_table[DETECT_CIPSERVICE].name = "cip_service"; //rule keyword
	sigmatch_table[DETECT_CIPSERVICE].desc = "Rules for detecting CIP Service ";
	sigmatch_table[DETECT_CIPSERVICE].url = "www.solananetworks.com";
	sigmatch_table[DETECT_CIPSERVICE].Match = DetectCipServiceMatch;
	sigmatch_table[DETECT_CIPSERVICE].Setup = DetectCipServiceSetup;
	sigmatch_table[DETECT_CIPSERVICE].Free = DetectCipServiceFree;
	sigmatch_table[DETECT_CIPSERVICE].RegisterTests
			= DetectCipServiceRegisterTests;

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
		Packet *p, Signature *s, SigMatch *m)
{
	int ret = 0;
	DetectCipServiceData *cipserviced = (DetectCipServiceData *) m->ctx;


	if (PKT_IS_PSEUDOPKT(p)) {
		SCLogDebug("Packet is fake");
	}

	if (PKT_IS_IPV4(p)) {
		/* ipv4 pkt */
	} else if (PKT_IS_IPV6(p)) {
		SCLogDebug("Packet is IPv6");
		return ret;
	} else {
		SCLogDebug("Packet is not IPv4 or IPv6");
		return ret;
	}


	ENIP_DATA enip_data;
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
	} else {
		return 0;
	}

	int status = DecodeENIP(p, &enip_data); //perform EtherNet/IP decoding

	if (status != 0)
	{
		//PrintENIP(&enip_data); //print gathered ENIP data
		ret = CIPServiceMatch(p, &enip_data, cipserviced); //check if rule matches
	}

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

//	SCLogDebug("DetectCipServiceParse - rule string  %s\n", rulestr);

	cipserviced = SCMalloc(sizeof(DetectCipServiceData));

	if (unlikely(cipserviced == NULL))
		goto error;


	char* token;
	int var;
	int input[3];
	int i = 0;

	token = strtok (rulestr, delims);
	while (token != NULL)
	{
		if (i > 2) //for now only need 3 parameters
		{
			printf("DetectEnipCommandParse: Too many parameters\n");
		   	goto error;
		}

		if (!isdigit((int) *token))
		{
			printf("DetectCipServiceParse - Parameter Error %s\n", token);
			goto error;
		}

		unsigned long num = atol(token);
		if ((num > MAX_CIP_SERVICE) && (i == 0))//if service greater than 7 bit
		{
			printf("DetectEnipCommandParse: Invalid CIP service %lu\n", num);
			goto error;
		}
		else if ((num > MAX_CIP_CLASS) && (i == 1))//if service greater than 16 bit
		{
			printf("DetectEnipCommandParse: Invalid CIP class %lu\n", num);
			goto error;
		}
		else if ((num > MAX_CIP_ATTRIBUTE) && (i == 2))//if service greater than 16 bit
		{
			printf("DetectEnipCommandParse: Invalid CIP attribute %lu\n", num);
			goto error;
		}

	    sscanf (token, "%d", &var);
	    input[i++] = var;

	    token = strtok (NULL, delims);
	}

	cipserviced->cipservice = input[0];
	cipserviced->cipclass = input[1];
	cipserviced->cipattribute = input[2];
	cipserviced->tokens = i;


//	SCLogDebug("DetectCipServiceParse - tokens %d\n", cipserviced->tokens);
//	SCLogDebug("DetectCipServiceParse - service %d\n", cipserviced->cipservice );
//	SCLogDebug("DetectCipServiceParse - class %d\n", cipserviced->cipclass );
//	SCLogDebug("DetectCipServiceParse - attribute %d\n", cipserviced->cipattribute );

	return cipserviced;

	error: if (cipserviced)
		SCFree(cipserviced);
	printf("DetectCipServiceParse - Error Parsing Parameters\n");
	return NULL;
}

/**
 * \brief this function is used to acipserviced the parsed cip_service data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param helloworldstr pointer to the user provided helloworld options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCipServiceSetup(DetectEngineCtx *de_ctx, Signature *s,
		char *rulestr)
{
	DetectCipServiceData *cipserviced = NULL;
	SigMatch *sm = NULL;

	cipserviced = DetectCipServiceParse(rulestr);
	if (cipserviced == NULL)
		goto error;

	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	sm->type = DETECT_CIPSERVICE;
	sm->ctx = (void *) cipserviced;

	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
	s->flags |= SIG_FLAG_REQUIRE_PACKET;

	return 0;

	error: if (cipserviced != NULL)
		DetectCipServiceFree(cipserviced);
	if (sm != NULL)
		SCFree(sm);
	printf("DetectCipServiceSetup - Error\n");
	return -1;
}

/**
 * \brief this function will free memory associated with DetectCipServiceData
 *
 * \param ptr pointer to DetectCipServiceData
 */
void DetectCipServiceFree(void *ptr) {
	DetectCipServiceData *cipserviced = (DetectCipServiceData *) ptr;
	SCFree(cipserviced);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectCipServiceParseTest01 (void)
{
	DetectCipServiceData *cipserviced = NULL;
	uint8_t res = 0;

	cipserviced = DetectCipServiceParse("1");
	if (cipserviced != NULL)
	{
		if (cipserviced->cipservice == 1)
		res = 1;

		DetectCipServiceFree(cipserviced);
	}

	return res;
}

static int DetectCipServiceSignatureTest01 (void)
{
	uint8_t res = 0;

	DetectEngineCtx *de_ctx = DetectEngineCtxInit();
	if (de_ctx == NULL)
	goto end;

	Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (cip_service:1; sid:1; rev:1;)");
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

/* rule function prototypes */
static int DetectEnipCommandMatch(ThreadVars *, DetectEngineThreadCtx *,
		Packet *, Signature *, SigMatch *);
static int DetectEnipCommandSetup(DetectEngineCtx *, Signature *, char *);
static void DetectEnipCommandFree(void *);
static void DetectEnipCommandRegisterTests(void);

/**
 * \brief Registration function for enip_command: keyword
 */
void DetectEnipCommandRegister(void)
{
	sigmatch_table[DETECT_ENIPCOMMAND].name = "enip_command"; //rule keyword
	sigmatch_table[DETECT_ENIPCOMMAND].desc = "Rules for detecting EtherNet/IP command";
	sigmatch_table[DETECT_ENIPCOMMAND].url = "www.solananetworks.com";
	sigmatch_table[DETECT_ENIPCOMMAND].Match = DetectEnipCommandMatch;
	sigmatch_table[DETECT_ENIPCOMMAND].Setup = DetectEnipCommandSetup;
	sigmatch_table[DETECT_ENIPCOMMAND].Free = DetectEnipCommandFree;
	sigmatch_table[DETECT_ENIPCOMMAND].RegisterTests
			= DetectEnipCommandRegisterTests;

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
		Packet *p, Signature *s, SigMatch *m)
{
	int ret = 0;
	DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *) m->ctx;


	if (PKT_IS_PSEUDOPKT(p))
	{
		SCLogDebug("Packet is fake");
	}

	if (PKT_IS_IPV4(p))
	{
		/* ipv4 pkt */
	} else if (PKT_IS_IPV6(p)) {
		SCLogDebug("Packet is IPv6");
		return ret;
	} else {
		SCLogDebug("Packet is not IPv4 or IPv6");
		return ret;
	}


	ENIP_DATA enip_data;
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
	} else {
		return 0;
	}

	//    SCLogDebug("CIPSERVICE %d\n",enipcmdd->enipcommand);

	int status = DecodeENIP(p, &enip_data); //perform EtherNet/IP decoding

	if (status > 0)
	{
		if (enipcmdd->enipcommand == enip_data.header.command) //check if rule matches
		{
			ret = 1;
		}
	}

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

	} else {
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
 * \brief this function is used to enipcmdd the parsed cip_service data into the current signature
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

	enipcmdd = DetectEnipCommandParse(rulestr);
	if (enipcmdd == NULL)
		goto error;

	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	sm->type = DETECT_ENIPCOMMAND;
	sm->ctx = (void *) enipcmdd;

	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
	s->flags |= SIG_FLAG_REQUIRE_PACKET;

	return 0;

	error: if (enipcmdd != NULL)
		DetectEnipCommandFree(enipcmdd);
	if (sm != NULL)
		SCFree(sm);
	printf("DetectEnipCommandSetup - Error\n");
	return -1;
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
 * \test description of the test
 */

static int DetectEnipCommandParseTest01 (void)
{
	DetectEnipCommandData *enipcmdd = NULL;
	uint8_t res = 0;

	enipcmdd = DetectEnipCommandParse("1");
	if (enipcmdd != NULL)
	{
		if (enipcmdd->enipcommand == 1)
		res = 1;

		DetectEnipCommandFree(enipcmdd);
	}

	return res;
}

static int DetectEnipCommandSignatureTest01 (void)
{
	uint8_t res = 0;

	DetectEngineCtx *de_ctx = DetectEngineCtxInit();
	if (de_ctx == NULL)
	goto end;

	Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (enip_command:1; sid:1; rev:1;)");
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








