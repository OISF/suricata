#ifndef __UTIL_VAR_H__
#define __UTIL_VAR_H__

typedef struct _GenericVar {
    u_int8_t type;
    u_int16_t idx;
    struct _GenericVar *next;
} GenericVar;

void GenericVarFree(GenericVar *);
void GenericVarAppend(GenericVar **, GenericVar *);
void GenericVarRemove(GenericVar **, GenericVar *);

#endif /* __UTIL_VAR_H__ */

