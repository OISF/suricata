








int DetectWatchListMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectWatchlistSetup (DetectEngineCtx *, Signature *, char *);
void DetectWatchlistFree (void *);
void WatchListRegisterTests(void);


IPReputationCtx *_watchlistCtx = 0;

void DetectIPRepRegister (void) {
    sigmatch_table[DETECT_IPREP].name = "ipwatch";
    sigmatch_table[DETECT_IPREP].Match = DetectWatchListMatch;
    sigmatch_table[DETECT_IPREP].Setup = DetectWatchlistSetup;
    sigmatch_table[DETECT_IPREP].Free  = DetectWatchlistFree;
    sigmatch_table[DETECT_IPREP].RegisterTests = WatchListRegisterTests;
    sigmatch_table[DETECT_IPREP].flags |= SIGMATCH_IPONLY_COMPAT;
}

static int DetectWatchlistSetup(DetectEngineCtx *, Signature *, char *) 
{
	if (_watchlistCtx == 0) {
		_watchlistCtx = (IPReputationCtx *)SCMalloc(sizeof(IPReputationCtx));
		memset(_watchlistCtx,0,sizeof(IPReputationCtx));

		 sm = SigMatchAlloc();
		 if (sm == NULL)
		        goto error;

		sm->type = DETECT_IPWATCH;
		SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	}
	return 0;
error:
	free(_watchlistCtx);
	return -1;
}
