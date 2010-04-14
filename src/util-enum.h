/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_ENUM_H__
#define __UTIL_ENUM_H__

typedef struct SCEnumCharMap_ {
    char *enum_name;
    int enum_value;
} SCEnumCharMap;

int SCMapEnumNameToValue(const char *, SCEnumCharMap *);

const char * SCMapEnumValueToName(int, SCEnumCharMap *);

#endif /* __UTIL_ENUM_H__ */
