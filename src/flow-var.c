/* implement per flow vars */

/* TODO
 * - move away from a linked list implementation
 * - use different datatypes, such as string, int, etc.
 * - have more than one instance of the same var, and be able to match on a 
 *   specific one, or one all at a time. So if a certain capture matches
 *   multiple times, we can operate on all of them.
 */

#include <ctype.h>
#include "threads.h"
#include "flow-var.h"
#include "flow.h"

/* puts a new value into a flowvar */
void FlowVarUpdate(FlowVar *fv, u_int8_t *value, u_int16_t size) {
    if (fv->value) free(fv->value);
    fv->value = value;
    fv->value_len = size;
}

/* get the flowvar with name 'name' from the flow
 *
 * name is a normal string*/
FlowVar *FlowVarGet(Flow *f, char *name) {
    FlowVar *fv = f->flowvar;

    for (;fv != NULL; fv = fv->next) {
        if (fv->name && strcmp(fv->name, name) == 0)
            return fv;
    }

    return NULL;
}

/* add a flowvar to the flow, or update it */
void FlowVarAdd(Flow *f, char *name, u_int8_t *value, u_int16_t size) {
    //printf("Adding flow var \"%s\" with value(%d) \"%s\"\n", name, size, value);

    mutex_lock(&f->m);

    FlowVar *fv = FlowVarGet(f, name);
    if (fv == NULL) {
        fv = malloc(sizeof(FlowVar));
        if (fv == NULL)
            goto out;

        fv->name = name;
        fv->value = value;
        fv->value_len = size;
        fv->next = NULL;

        FlowVar *tfv = f->flowvar;
        if (f->flowvar == NULL) f->flowvar = fv;
        else {
            while(tfv) {
                if (tfv->next == NULL) {
                    tfv->next = fv;
                    goto out;
                }
                    
                tfv = tfv->next;
            }
        }
    } else {
        FlowVarUpdate(fv, value, size);
    }

out:
    mutex_unlock(&f->m);
}

void FlowVarFree(FlowVar *fv) {
    if (fv == NULL)
        return;

    fv->name = NULL;
    if (fv->value) free(fv->value);

    if (fv->next) FlowVarFree(fv->next);
}

void FlowVarPrint(FlowVar *fv) {
    u_int16_t i;

    if (fv == NULL)
        return;

    printf("Name \"%s\", Value \"", fv->name);
    for (i = 0; i < fv->value_len; i++) {
        if (isprint(fv->value[i])) printf("%c", fv->value[i]);
        else                       printf("\\%02X", fv->value[i]);
    }
    printf("\", Len \"%u\"\n", fv->value_len);

    FlowVarPrint(fv->next);
}

