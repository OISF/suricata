/* implement per packet vars */

/* TODO
 * - move away from a linked list implementation
 * - use different datatypes, such as string, int, etc.
 * - have more than one instance of the same var, and be able to match on a 
 *   specific one, or one all at a time. So if a certain capture matches
 *   multiple times, we can operate on all of them.
 */

#include "suricata-common.h"
#include "decode.h"
#include "pkt-var.h"
#include "util-debug.h"

/* puts a new value into a pktvar */
void PktVarUpdate(PktVar *pv, uint8_t *value, uint16_t size) {
    if (pv->value) SCFree(pv->value);
    pv->value = value;
    pv->value_len = size;
}

/* get the pktvar with name 'name' from the pkt
 *
 * name is a normal string*/
PktVar *PktVarGet(Packet *p, char *name) {
    PktVar *pv = p->pktvar;

    for (;pv != NULL; pv = pv->next) {
        if (pv->name && strcmp(pv->name, name) == 0)
            return pv;
    }

    return NULL;
}

/* add a pktvar to the pkt, or update it */
void PktVarAdd(Packet *p, char *name, uint8_t *value, uint16_t size) {
    //printf("Adding packet var \"%s\" with value(%" PRId32 ") \"%s\"\n", name, size, value);

    PktVar *pv = PktVarGet(p, name);
    if (pv == NULL) {
        pv = SCMalloc(sizeof(PktVar));
        if (pv == NULL)
            return;

        pv->name = name;
        pv->value = value;
        pv->value_len = size;
        pv->next = NULL;

        PktVar *tpv = p->pktvar;
        if (p->pktvar == NULL) p->pktvar = pv;
        else {
            while(tpv) {
                if (tpv->next == NULL) {
                    tpv->next = pv;
                    return;
                }
                    
                tpv = tpv->next;
            }
        }
    } else {
        PktVarUpdate(pv, value, size);
    }
}

void PktVarFree(PktVar *pv) {
    if (pv == NULL)
        return;

    pv->name = NULL;
    if (pv->value != NULL)
        SCFree(pv->value);
    PktVar *pv_next = pv->next;

    SCFree(pv);

    if (pv_next != NULL)
        PktVarFree(pv_next);
}

void PktVarPrint(PktVar *pv) {
    uint16_t i;

    if (pv == NULL)
        return;

    printf("Name \"%s\", Value \"", pv->name);
    for (i = 0; i < pv->value_len; i++) {
        if (isprint(pv->value[i])) printf("%c", pv->value[i]);
        else                       printf("\\%02X", pv->value[i]);
    }
    printf("\", Len \"%" PRIu32 "\"\n", pv->value_len);

    PktVarPrint(pv->next);
}

