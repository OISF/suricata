/* implement per flow vars */

/* TODO
 * - move away from a linked list implementation
 * - use different datatypes, such as string, int, etc.
 * - have more than one instance of the same var, and be able to match on a 
 *   specific one, or one all at a time. So if a certain capture matches
 *   multiple times, we can operate on all of them.
 */

#include "eidps-common.h"
#include "threads.h"
#include "flow-var.h"
#include "flow.h"
#include "detect.h"

/* puts a new value into a flowvar */
void FlowVarUpdate(FlowVar *fv, uint8_t *value, uint16_t size) {
    if (fv->value) free(fv->value);
    fv->value = value;
    fv->value_len = size;
}

/* get the flowvar with name 'name' from the flow
 *
 * name is a normal string*/
FlowVar *FlowVarGet(Flow *f, uint8_t idx) {
    GenericVar *gv = f->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWVAR && gv->idx == idx)
            return (FlowVar *)gv;
    }

    return NULL;
}

/* add a flowvar to the flow, or update it */
void FlowVarAdd(Flow *f, uint8_t idx, uint8_t *value, uint16_t size) {
    //printf("Adding flow var \"%s\" with value(%" PRId32 ") \"%s\"\n", name, size, value);

    sc_mutex_lock(&f->m);

    FlowVar *fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        fv = malloc(sizeof(FlowVar));
        if (fv == NULL)
            goto out;

        fv->type = DETECT_FLOWVAR;
        fv->idx = idx;
        fv->value = value;
        fv->value_len = size;
        fv->next = NULL;

        GenericVarAppend(&f->flowvar, (GenericVar *)fv);
    } else {
        FlowVarUpdate(fv, value, size);
    }

out:
    sc_mutex_unlock(&f->m);
}

void FlowVarFree(FlowVar *fv) {
    if (fv == NULL)
        return;

    if (fv->value != NULL)
        free(fv->value);

    free(fv);
}

void FlowVarPrint(GenericVar *gv) {
    uint16_t i;

    if (gv == NULL)
        return;

    if (gv->type == DETECT_FLOWVAR) {
        FlowVar *fv = (FlowVar *)gv;

        printf("Name idx \"%" PRIu32 "\", Value \"", fv->idx);
        for (i = 0; i < fv->value_len; i++) {
            if (isprint(fv->value[i])) printf("%c", fv->value[i]);
            else                       printf("\\%02X", fv->value[i]);
        }
        printf("\", Len \"%" PRIu32 "\"\n", fv->value_len);
    }
    FlowVarPrint(gv->next);
}

