#include "suricata-common.h"
#include "capture-hooks.h"

static CaptureOnPacketWithAlertsHook g_on_alerts_hook = NULL;
static CaptureOnPseudoPacketCreatedHook g_on_pseudo_created_hook = NULL;

void CaptureHooksSet(
        CaptureOnPacketWithAlertsHook on_alerts, CaptureOnPseudoPacketCreatedHook on_pseudo_created)
{
    g_on_alerts_hook = on_alerts;
    g_on_pseudo_created_hook = on_pseudo_created;
}

void CaptureHooksOnPacketWithAlerts(const Packet *p)
{
    if (g_on_alerts_hook != NULL) {
        g_on_alerts_hook(p);
    }
}

void CaptureHooksOnPseudoPacketCreated(Packet *p)
{
    if (g_on_pseudo_created_hook != NULL) {
        g_on_pseudo_created_hook(p);
    }
}
