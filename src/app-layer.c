#include "suricata-common.h"
#include "app-layer.h"
#include "stream-tcp-private.h"
#include "util-debug.h"

/** \brief Get the active app layer proto from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval proto (ALPROTO_UNKNOWN if no proto yet) */
uint16_t AppLayerGetProtoFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    SCReturnUInt(ssn->alproto);
}

/** \brief Get the active app layer state from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnPtr(NULL, "void");
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL || ssn->aldata == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];

    SCLogDebug("p->flow %p", p->flow);
    SCReturnPtr(alstate, "void");
}

/** \brief Get the active app layer state from the flow
 *  \param f flow pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    SCEnter();

    if (f == NULL)
        SCReturnPtr(NULL, "void");

    TcpSession *ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL || ssn->aldata == NULL)
        SCReturnPtr(NULL, "void");

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];
    SCReturnPtr(alstate, "void");
}

