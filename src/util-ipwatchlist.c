
#include "util-ipwatchlist.h"



 int CreateIpWatchListCtx() {
	if (_ipwatchlistCtx == NULL) {
			_ipwatchlistCtx = (IPWatchListCtx *)SCMalloc(sizeof(IPWatchListCtx));
			if (unlikely(_ipwatchlistCtx == NULL))
				goto error;

			memset(_ipwatchlistCtx,0,sizeof(IPWatchListCtx));

			_ipwatchlistCtx->watchListIPV4_tree = SCRadixCreateRadixTree(SCWatchListFreeData, NULL);
		    if (_ipwatchlistCtx->watchListIPV4_tree == NULL) {
		        SCLogDebug("Error initializing Reputation IPV4 module");
		        return NULL;
		    }

		    SCLogDebug("Reputation IPV4 module initialized");

		    _ipwatchlistCtx->watchListIPV6_tree = SCRadixCreateRadixTree(SCWatchListFreeData, NULL);
		    if (_ipwatchlistCtx->watchListIPV6_tree == NULL) {
		        SCLogDebug("Error initializing Reputation IPV6 module");
		        return NULL;
		    }

		    SCLogDebug("Reputation IPV6 module initialized");
		    if (SCMutexInit(&_ipwatchlistCtx->watchlistIPV4_lock, NULL) != 0) {
		        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
		        exit(EXIT_FAILURE);
		    }
		    if (SCMutexInit(&_ipwatchlistCtx->watchlistIPV6_lock, NULL) != 0) {
		        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
		        exit(EXIT_FAILURE);
		    }


	}
	return 0;

	error:
		SCFree(_ipwatchlistCtx);
		return -1;
}

 void SCReputationFreeData(void *) {


 }
 int addIpaddressToWatchList(const char * msg, const char* adr) {

	 WatchListData *data = NULL;

	  /* IPV6 or IPV4? */
	if (strchr(adr, ':') != NULL) {
		SCLogDebug("STIX IP Watch List adding ipv6 address %s", adr);
		if (SCRadixAddKeyIPV6String(adr, _ipwatchlistCtx->watchListIPV6_tree, data) == NULL) {
			SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed to "
					"add ipv6 %s, ignoring", adr);
		}
	} else {
		SCLogDebug("LIBHTP adding ipv4 server %s at %s: %p", s->name, pval->val,
				cfg_prec->cfg);
		if (SCRadixAddKeyIPV4String(adr,  _ipwatchlistCtx->watchListIPV6_tree, data) == NULL) {
			SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed "
					"to add ipv4 server %s, ignoring",adr);
		}
	}

 }
