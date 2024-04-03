/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  LIB packet and stream decoding support
 *
 */

#ifndef __SOURCE_LIB_H__
#define __SOURCE_LIB_H__

#include "tm-threads.h"

/** \brief register a "Decode" module for suricata as a library.
 *
 *  The "Decode" module is the first module invoked when processing a packet */
void TmModuleDecodeLibRegister(void);

/** \brief process a single packet.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the raw packet.
 * \param datalink              Datalink type.
 * \param ts                    Timeval structure.
 * \param len                   Packet length.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param flags                 Packet flags (packet checksum, rule profiling...).
 * \param iface                 Sniffing interface this packet comes from (can be NULL).
 * \return                      Error code.
 */
int TmModuleLibHandlePacket(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, uint32_t tenant_id, uint32_t flags, const char *iface);
#endif /* __SOURCE_LIB_H__ */
