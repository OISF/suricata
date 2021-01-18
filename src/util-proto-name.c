/* Copyright (C) 2007-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * File to provide the protocol names based on protocol numbers defined in the
 * specified protocol file.
 */

#include "suricata-common.h"
#include "util-proto-name.h"
#include "util-byte.h"

/** Lookup array to hold the information related to known protocol
 *  in /etc/protocols */
char *known_proto[256];
static int init_once = 0;

static void SetDefault(const uint8_t proto, const char *string)
{
    if (known_proto[proto] == NULL) {
        known_proto[proto] = SCStrdup(string);
        if (unlikely(known_proto[proto] == NULL)) {
            FatalError(SC_ERR_MEM_ALLOC, "failed to alloc protocol name");
        }
    }
}

/**
 *  \brief  Function to load the protocol names from the specified protocol
 *          file.
 */
void SCProtoNameInit()
{
    BUG_ON(init_once);
    init_once++;
    memset(known_proto, 0x00, sizeof(known_proto));

    /* Load the known protocols name from the /etc/protocols file */
    FILE *fp = fopen(PROTO_FILE,"r");
    if (fp != NULL) {
        char line[200];
        char *ptr = NULL;

        while(fgets(line, sizeof(line), fp) != NULL) {
            if (line[0] == '#')
                continue;

            char *name = strtok_r(line," \t", &ptr);
            if (name == NULL)
                continue;

            char *proto_ch = strtok_r(NULL," \t", &ptr);
            if (proto_ch == NULL)
                continue;

            uint8_t proto;
            if (StringParseUint8(&proto, 10, 0, (const char *)proto_ch) < 0)
                continue;

            char *cname = strtok_r(NULL, " \t", &ptr);

            if (known_proto[proto] != NULL) {
                SCFree(known_proto[proto]);
            }

            if (cname != NULL) {
                known_proto[proto] = SCStrdup(cname);
            } else {
                known_proto[proto] = SCStrdup(name);
            }
            if (unlikely(known_proto[proto] == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed proto name allocation");
                continue;
            }
            int proto_len = strlen(known_proto[proto]);
            if (proto_len > 0 && known_proto[proto][proto_len - 1] == '\n')
                known_proto[proto][proto_len - 1] = '\0';
        }
        fclose(fp);
    }

    SetDefault(IPPROTO_SCTP, "SCTP");
}

/**
 * \brief   Function to check if the received protocol number is valid and do
 *          we have corresponding name entry for this number or not.
 *
 * \param proto Protocol number to be validated
 * \retval ret On success returns true otherwise false
 */
bool SCProtoNameValid(uint16_t proto)
{
    return (proto <= 255 && known_proto[proto] != NULL);
}

/**
 *  \brief  Function to clears the memory used in storing the protocol names.
 */
void SCProtoNameDeInit()
{
    int cnt;
    /* clears the memory of loaded protocol names */
    for (cnt = 0; cnt < 255; cnt++) {
        if (known_proto[cnt] != NULL)
            SCFree(known_proto[cnt]);
    }
}
