#ifndef __WIN32_MISC_H__
#define __WIN32_MISC_H__

#define index strchr
#define rindex strrchr

#define strtok_r(s,d,p) strtok(s,d)

const char* inet_ntop(int af, const void *src, char *dst, uint32_t cnt);
int inet_pton(int af, const char *src, void *dst);

#define geteuid() (0)

#endif
