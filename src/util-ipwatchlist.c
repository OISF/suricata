
#include "suricata-common.h"


IPReputationCtx *_ipwatchlistCtx = NULL;

static int CreateIpWatchListCtx() {
	if (_ipwatchlistCtx == NULL) {
			_watchlistCtx = (IPReputationCtx *)SCMalloc(sizeof(IPReputationCtx));
			if (unlikely(_ipwatchlistCtx == NULL))
				goto error;

			memset(_ipwatchlistCtx,0,sizeof(IPReputationCtx));
	}
	return 0;

	error:
	SCFree(_ipwatchlistCtx);
	return -1;
}
