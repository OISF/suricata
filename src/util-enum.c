/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include <stdio.h>
#include <string.h>

#include "util-enum.h"

/**
 * \brief Maps a string name to an enum value from the supplied table.  Please
 *        specify the last element of any map table with a {NULL, -1}.  If
 *        missing, you will be welcomed with a segfault :)
 *
 * \param enum_name Character string that has to be mapped to an enum value
 *                  from the table
 * \param table     Enum-Char table, from which the mapping is retrieved
 *
 * \retval result The enum_value for the enum_name string or -1 on failure
 */
int SCMapEnumNameToValue(const char *enum_name, SCEnumCharMap *table)
{
    int result = -1;

    if (enum_name == NULL || table == NULL) {
        printf("Invalid argument(s) passed into SCMapEnumNameToValue\n");
        return -1;
    }

    for (; table->enum_name != NULL; table++) {
        if (strcasecmp(table->enum_name, enum_name) == 0) {
            result = table->enum_value;
            break;
        }
    }

    return result;
}

/**
 * \brief Maps an enum value to a string name, from the supplied table
 *
 * \param enum_value Enum_value that has to be mapped to a string_value
 *                   from the table
 * \param table      Enum-Char table, from which the mapping is retrieved
 *
 * \retval result The enum_name for the enum_value supplied or NULL on failure
 */
const char * SCMapEnumValueToName(int enum_value, SCEnumCharMap *table)
{
    if (table == NULL) {
        printf("Invalid argument(s) passed into SCMapEnumValueToName\n");
        return NULL;
    }

    for (; table->enum_name != NULL; table++) {
        if (table->enum_value == enum_value) {
            return table->enum_name;
        }
    }

    printf("A enum by the value %d doesn't exist in this table\n", enum_value);

    return NULL;
}
