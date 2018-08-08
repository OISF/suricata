#ifndef __DECODE_TRILL_H__
#define __DECODE_TRILL_H__

#define ETHERNET_TYPE_TRILL           0x22F3
#define TRILL_HEADER_LEN              6

typedef struct TRILLHdr_ {
	uint16_t trill_info;
	uint16_t egress_nick;
	uint16_t ingress_nick;
} __attribute__((__packet__)) TRILLHdr;

#endif /* __DECODE_TRILL_H__ */