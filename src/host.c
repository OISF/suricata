#include "suricata-common.h"
#include "host.h"

Host *HostAlloc(void) {
    Host *h = malloc(sizeof(Host));
    if (h == NULL)
        goto error;

    return h;

error:
    return NULL;
}

void HostFree(Host *h) {
    free(h);
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

