/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __ENUM_H__
#define __ENUM_H__

typedef struct _SCEnumCharMap {
    char *enum_name;
    int enum_value;
} SCEnumCharMap;

int SCMapEnumNameToValue(const char *, SCEnumCharMap *);

const char * SCMapEnumValueToName(int, SCEnumCharMap *);

#endif /* __ENUM_H__ */
