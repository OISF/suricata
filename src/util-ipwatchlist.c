#include "util-ipwatchlist.h"
#include "util-ip.h"

int CreateIpWatchListCtx() {
	if (_ipwatchlistCtx == NULL) {
		_ipwatchlistCtx = (IPWatchListCtx *) SCMalloc(sizeof(IPWatchListCtx));
		if (unlikely(_ipwatchlistCtx == NULL))
			goto error;

		memset(_ipwatchlistCtx, 0, sizeof(IPWatchListCtx));

		_ipwatchlistCtx->watchListIPV4_tree = SCRadixCreateRadixTree(
				SCWatchListFreeData, NULL);
		if (_ipwatchlistCtx->watchListIPV4_tree == NULL) {
			SCLogDebug("Error initializing Reputation IPV4 module");
			return NULL;
		}

		SCLogDebug("Reputation IPV4 module initialized");

		_ipwatchlistCtx->watchListIPV6_tree = SCRadixCreateRadixTree(
				SCWatchListFreeData, NULL);
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
	_ipwatchlistCtx = NULL;
	return -1;
}

int CreateIpWatchListCtxFree() {
	SCFree(_ipwatchlistCtx);
	_ipwatchlistCtx = NULL;
	return 1;
}

int addIpaddressToWatchList(const char * msg, const char* adr) {

	if (_ipwatchlistCtx == NULL) {
		SCLogWarning("STIX Add to IP Watch List was called when Context was Null %s", ".");
		return 0;
	}

	WatchListData *data = NULL;

	/* IPV6 or IPV4? */
	if (strchr(adr, ':') != NULL) {

		SCLogDebug("STIX IP Watch List adding ipv6 address %s", adr);

		struct in6_addr addr;
		if (inet_pton(AF_INET6, adr, &addr) <= 0) {
			return 0;
		}
		SCRadixNode* node = SCRadixFindKeyIPV4ExactMatch(
				(uint8_t *) &addr.s6_addr, _ipwatchlistCtx->watchListIPV6_tree)
		if (node == NULL) {
			WatchListData * data = SCMalloc(sizeof(WatchListData));
			memset(data, 0, sizeof(WatchListData));

			if (SCRadixAddKeyIPV6String(adr,
					_ipwatchlistCtx->watchListIPV6_tree, data) == NULL) {
				SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed to "
						"add ipv6 %s, ignoring", adr);
				return 0;
			}
		} else {
			WatchListData * data = SC_RADIX_NODE_USERDATA(node, WatchListData);
		}
	} else {
		SCLogDebug("STIX IP Watch Lust adding ipv4 address %s", adr);
		struct in_addr addr;

		if (inet_pton(AF_INET, adr, &addr) <= 0) {
			return 0;
		}
		SCRadixNode* node = SCRadixFindKeyIPV4ExactMatch(
				(uint8_t *) &addr.s_addr, _ipwatchlistCtx->watchListIPV4_tree);
		if (node == NULL) {
			WatchListData * data = SCMalloc(sizeof(WatchListData));
			memset(data, 0, sizeof(WatchListData));

			if (SCRadixAddKeyIPV4String(adr,
					_ipwatchlistCtx->watchListIPV4_tree, data) == NULL) {
				SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed "
						"to add ipv4 server %s, ignoring", adr);
				return 0;
			}
		} else {
			WatchListData * data = SC_RADIX_NODE_USERDATA(node, WatchListData); //(node->prefix->user_data->user);
		}
	}
	int count = data->msg_cnt;
	if (count >= MAX_WACTCH_LIST_MSG) {
		count = 0;
	}
	data->msgs[count] = msg;
	return 1;
}

void SCWatchListFreeData(void * user) {
	WatchListData * data = (WatchListData *) user;
	for (int i = 0; i < data->msg_cnt; i++) {
		char * msg = data->msgs[i];
		SCFree(msg);
		data->msgs[i] = NULL;
	}
	data->msg_cnt = 0;
}

char * isIPWatched(uint8_t* addr , char* ipType) {
	switch(ipType) {
	case AF_INET:
		SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(addr, _ipwatchlistCtx->watchListIPV4_tree);
		if (node != NULL) {
			return SC_RADIX_NODE_USERDATA(node, WatchListData)->msgs[0];
		}else{
			return NULL;
		}
	case AF_INET6:
			SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(addr, _ipwatchlistCtx->watchListIPV6_tree);
			if (node != NULL) {
				return SC_RADIX_NODE_USERDATA(node, WatchListData)->msgs[0];
			}else{
				return NULL;
			}
	}
	return NULL;
}


int DetectMatch(Packet *p){
	uint8_t * src =  GET_IPV4_SRC_ADDR_PTR(p);
	char src_type = p->src->family;
	uint8_t * dst =  GET_IPV4_DST_ADDR_PTR(p)
	char dst_type = p->dst->family;

	if (isIPWatched(src, src_type) != NULL) {
		return 1;
	}

	if (isIPWatched(dst, dst_type) != NULL) {
			return 1;
	}

	return 0;
}
