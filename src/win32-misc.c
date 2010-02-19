#ifdef OS_WIN32

#include "suricata-common.h"
#include "win32-misc.h"

int setenv(const char *name, const char *value, int overwrite)
{
	if (overwrite || NULL == getenv(name)) {
		char *str = SCMalloc(strlen(name) + strlen(value) + 2);
		sprintf(str, "%s=%s", name, value);
		putenv(str);
		SCFree(str);
	}
}

int unsetenv(const char *name)
{
	char *str = SCMalloc(strlen(name) + 2);
	sprintf(str, "%s=", name);
	putenv(str);
	SCFree(str);
}

const char* inet_ntop(int af, const void *src, char *dst, uint32_t cnt)
{
	if (af == AF_INET)
	{
		struct sockaddr_in in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, src, sizeof(struct in_addr));
		if (0 == getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST))
			return dst;
	}
	else if (af == AF_INET6)
	{
		struct sockaddr_in6 in6;
		memset(&in6, 0, sizeof(in6));
		in6.sin6_family = AF_INET6;
		memcpy(&in6.sin6_addr, src, sizeof(struct in_addr6));
		if (0 == getnameinfo((struct sockaddr *)&in6, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST))
			return dst;
	}
	return NULL;
}

int inet_pton(int af, const char *src, void *dst)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = af;

	struct addrinfo* result = NULL;
	if (0 != getaddrinfo(src, NULL, &hints, &result))
		return -1;

	if (result) {
		if (result->ai_family == AF_INET) {
			struct sockaddr_in* in = (struct sockaddr_in*)result->ai_addr;
			memcpy(dst, &in->sin_addr, 4);
		}
		else if (result->ai_family == AF_INET6) {
			struct sockaddr_in6* in6 = (struct sockaddr_in6*)result->ai_addr;
			memcpy(dst, &in6->sin6_addr, 16);
		}
		else {
			freeaddrinfo(result);
			return -1;
		}

		freeaddrinfo(result);
		return 1;
	}

	return -1;
}

#endif /* OS_WIN32 */
