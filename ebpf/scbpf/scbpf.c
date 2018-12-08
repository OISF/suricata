#include <linux/unistd.h>
#include <linux/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <bpf/bpf.h>

#define BPF_F_ADD	(1 << 0)
#define BPF_F_GET	(1 << 1)

#define BPF_F_KEY	(1 << 2)
#define BPF_F_VAL	(1 << 3)
#define BPF_F_KEY_VAL	(BPF_F_KEY | BPF_F_VAL)

static void usage(void)
{
	printf("Usage: fds_example [...]\n");
	printf("       -F <file>   File to pin/get object\n");
	printf("       -A          |- add key\n");
	printf("       -G          `- get object\n");
	printf("       -k <key>    |- map key\n");
	printf("       -h          Display this help.\n");
}

static int bpf_do_map(const char *file, uint32_t flags, uint32_t key,
		      uint32_t value)
{
	int fd, ret;

	fd = bpf_obj_get(file);
	printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
	assert(fd > 0);

	if ((flags & BPF_F_ADD) == BPF_F_ADD) {
		ret = bpf_map_update_elem(fd, &key, &value, 0);
		printf("bpf: fd:%d u->(%u:%u) ret:(%d,%s)\n", fd, key, value,
		       ret, strerror(errno));
		assert(ret == 0);
	} else if (flags & BPF_F_GET) {
		ret = bpf_map_lookup_elem(fd, &key, &value);
		printf("bpf: fd:%d l->(%u):%u ret:(%d,%s)\n", fd, key, value,
		       ret, strerror(errno));
		assert(ret == 0);
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *file = NULL, *object = NULL;
	uint32_t key = 0, flags = 0;
	uint32_t value;
	int opt;

	while ((opt = getopt(argc, argv, "F:GAk:")) != -1) {
		switch (opt) {
		/* General args */
		case 'F':
			file = optarg;
			break;
		case 'G':
			flags |= BPF_F_GET;
			break;
		case 'A':
			flags |= BPF_F_ADD;
			break;
		case 'k':
			key = ntohl(inet_addr(optarg));
			printf("%u\n", key);
			flags |= BPF_F_KEY;
			break;
		default:
			goto out;
		}
	}

	return bpf_do_map(file, flags, key, value);
out:
	usage();
	return -1;
}
