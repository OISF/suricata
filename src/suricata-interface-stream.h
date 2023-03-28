/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Utility structs for library stream support.
 */

#ifndef __SURICATA_INTERFACE_STREAM_H__
#define __SURICATA_INTERFACE_STREAM_H__

#include <stdint.h>


/**
* \brief Enum representing the stream segment direction.
*
* \enum Direction
*/
enum StreamDirection {
    DIRECTION_TOSERVER = 0,
    DIRECTION_TOCLIENT
};

/**
* \brief Struct representing flow information.
*
* \struct FlowStreamInfo
*/
typedef struct {
    /* Source IP address (in network byte order). */
    struct {
        /* Family. */
        char family;

        union {
            uint32_t        address_un_data32[4]; /* type-specific field */
            uint16_t        address_un_data16[8]; /* type-specific field */
            uint8_t         address_un_data8[16]; /* type-specific field */
        };
    } src;

    /* Source port. */
    uint16_t sp;

    /* Destination IP address (in network byte order). */
    struct {
        // Family.
        char family;

        union {
            uint32_t        address_un_data32[4]; /* type-specific field */
            uint16_t        address_un_data16[8]; /* type-specific field */
            uint8_t         address_un_data8[16]; /* type-specific field */
        };
    } dst;

    /* Destination port. */
    uint16_t dp;

    /* Direction of the stream segment (0 to server, 1 to client). */
    enum StreamDirection direction;

    /* Timestamp of the stream segment. */
    struct timeval ts;
} FlowStreamInfo;

#endif /* __SURICATA_INTERFACE_STREAM_H__ */
