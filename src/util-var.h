#ifndef __UTIL_VAR_H__
#define __UTIL_VAR_H__

typedef struct GenericVar_ {
    uint8_t type;
    struct GenericVar_ *next;
    uint16_t idx;
} GenericVar;

void GenericVarFree(GenericVar *);
void GenericVarAppend(GenericVar **, GenericVar *);
void GenericVarRemove(GenericVar **, GenericVar *);

#endif /* __UTIL_VAR_H__ */

