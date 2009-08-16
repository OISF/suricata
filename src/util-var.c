#include "eidps-common.h"
#include "detect.h"

#include "util-var.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"

void GenericVarFree(GenericVar *gv) {
    if (gv == NULL)
        return;

    //printf("GenericVarFree: gv %p, gv->type %" PRIu32 "\n", gv, gv->type);
    GenericVar *next_gv = gv->next;

    switch (gv->type) {
        case DETECT_FLOWBITS:
        {
            FlowBit *fb = (FlowBit *)gv;
            //printf("GenericVarFree: fb %p, removing\n", fb);
            FlowBitFree(fb);
            break;
        }
        case DETECT_FLOWVAR:
        {
            FlowVar *fv = (FlowVar *)gv;
            FlowVarFree(fv);
            break;
        }
        case DETECT_PKTVAR:
        {
            PktVar *pv = (PktVar *)gv;
            PktVarFree(pv);
            break;
        }
        default:
        {
            printf("ERROR: GenericVarFree unknown type %" PRIu32 "\n", gv->type);
            break;
        }
    }

    GenericVarFree(next_gv);
}

void GenericVarAppend(GenericVar **list, GenericVar *gv) {
    gv->next = NULL;

    if (*list == NULL) {
        *list = gv;
    } else {
        GenericVar *tgv = *list;
        while(tgv) {
            if (tgv->next == NULL) {
                tgv->next = gv;
                return;
            }

            tgv = tgv->next;
        }
    }
}

void GenericVarRemove(GenericVar **list, GenericVar *gv) {
    if (*list == NULL)
        return;

    GenericVar *listgv = *list, *prevgv = NULL;
    while (listgv != NULL) {
        if (listgv == gv) {
            if (prevgv == NULL)
                *list = gv->next;
            else
                prevgv->next = gv->next;

            return;
        }

        prevgv = listgv;
        listgv = listgv->next;
    }
}

