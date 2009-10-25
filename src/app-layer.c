#include "eidps-common.h"
#include "app-layer.h"
#include "stream-tcp-private.h"

/** \brief Get the active app layer state from the packet */
void *AppLayerGetProtoStateFromPacket(Packet *p) {
    if (p == NULL || p->flow == NULL)
        return NULL;

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL || ssn->aldata == NULL)
        return NULL;

    void *alstate = ssn->aldata[ssn->alproto];
    return alstate;
}

/** \brief Get the active app layer state from the flow */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    if (f == NULL)
        return NULL;

    TcpSession *ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL || ssn->aldata == NULL)
        return NULL;

    void *alstate = ssn->aldata[ssn->alproto];
    return alstate;
}

