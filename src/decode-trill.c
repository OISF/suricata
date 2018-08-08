#include "suricata-common.h"
#include "decode.h"
#include "decode-trill.h"

#include "decode-events.h"

int DecodeTRILL(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
	StatsIncr(tv, dtv->counter_trill);

	if (unlikely(len < TRILL_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, TRILL_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->trillh = (TRILLHdr *)pkt;
    if (unlikely(p->trillh == NULL))
        return TM_ECODE_FAILED;

    DecodeEthernet(tv, dtv, p, pkt + TRILL_HEADER_LEN,
                    len - TRILL_HEADER_LEN, pq);
}