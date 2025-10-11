#ifndef SURICATA_CAPTURE_HOOKS_H
#define SURICATA_CAPTURE_HOOKS_H

#include "suricata-common.h"

struct Packet_;
typedef struct Packet_ Packet;

typedef void (*CaptureOnPacketWithAlertsHook)(const Packet *p);
typedef void (*CaptureOnPseudoPacketCreatedHook)(Packet *p);

/* Register/clear hooks (called by capture implementations) */
void CaptureHooksSet(CaptureOnPacketWithAlertsHook on_alerts,
        CaptureOnPseudoPacketCreatedHook on_pseudo_created);

/* Invoke hooks (called from generic code, safe if unset) */
void CaptureHooksOnPacketWithAlerts(const Packet *p);
void CaptureHooksOnPseudoPacketCreated(Packet *p);

#endif /* SURICATA_CAPTURE_HOOKS_H */
