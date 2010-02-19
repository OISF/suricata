#include "suricata-common.h"
#include "util-debug.h"
#include "host.h"

Host *HostAlloc(void) {
    Host *h = SCMalloc(sizeof(Host));
    if (h == NULL)
        goto error;

    return h;

error:
    return NULL;
}

void HostFree(Host *h) {
    SCFree(h);
}

Host *HostNew(Address *a) {
    Host *h = HostAlloc();
    if (h == NULL)
        goto error;

    /* copy address */

    /* set os and reputation to 0 */
    h->os = HOST_OS_UNKNOWN;
    h->reputation = HOST_REPU_UNKNOWN;

    return h;

error:
    return NULL;
}

