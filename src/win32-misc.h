#ifndef __WIN32_MISC_H__
#define __WIN32_MISC_H__

#define index strchr
#define rindex strrchr

#define strtok_r(s, d, p) strtok(s, d)

#define bzero(s, n) memset(s, 0, n)

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* O_NOFOLLOW */

int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);

const char* inet_ntop(int af, const void *src, char *dst, uint32_t cnt);
int inet_pton(int af, const char *src, void *dst);

#define geteuid() (0)

#endif
