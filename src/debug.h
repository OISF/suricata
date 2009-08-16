/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef DEBUG

#define DEBUGPRINT(format, args...) \
        printf("[%s:%" PRId32 "](%s) " format "\n", __FILE__, __LINE__, __FUNCTION__, ## args)

#else

#define DEBUGPRINT(format, args...)

#endif /* DEBUG */
#endif /* __DEBUG_H__ */

