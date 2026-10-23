/* Redmine #8777: send a valid UDP frame on one slot or as 0 + 1000 bytes.
 * Both layouts must produce the same frame for capture and inspection.
 * Both VALE ports are local; no physical network traffic is generated. */
#include <errno.h>
#include <fcntl.h>
#include <libnetmap.h>
#include <net/netmap_user.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FRAME_LEN 1000U
#define MARKER    "NETMAP_8777_TAIL_MARKER"

static void Be16(uint8_t *p, uint16_t n)
{
    p[0] = n >> 8;
    p[1] = n;
}

static uint16_t IpChecksum(const uint8_t *p, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2)
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static void MakeFrame(uint8_t frame[FRAME_LEN])
{
    memset(frame, 0, FRAME_LEN);
    /* Destination is a local VALE port; a valid IPv4/UDP frame is useful
     * for asserting that inspection of both slot layouts really ran. */
    frame[0] = 0x02;
    frame[5] = 0x02;
    frame[6] = 0x02;
    frame[11] = 0x01;
    Be16(frame + 12, 0x0800);
    uint8_t *ip = frame + 14;
    ip[0] = 0x45;
    Be16(ip + 2, FRAME_LEN - 14);
    ip[8] = 64;
    ip[9] = 17;
    ip[12] = 192;
    ip[13] = 0;
    ip[14] = 2;
    ip[15] = 10;
    ip[16] = 198;
    ip[17] = 51;
    ip[18] = 100;
    ip[19] = 20;
    Be16(ip + 10, IpChecksum(ip, 20));
    uint8_t *udp = ip + 20;
    Be16(udp, 44444);
    Be16(udp + 2, 55555);
    Be16(udp + 4, FRAME_LEN - 14 - 20);
    /* Zero UDP checksum is valid for IPv4. */
    for (size_t i = 42; i < FRAME_LEN; i++)
        frame[i] = (uint8_t)('A' + i % 26);
    memcpy(frame + FRAME_LEN - 64, MARKER, sizeof(MARKER) - 1);
}

static int SaveFrame(const char *path, const uint8_t frame[FRAME_LEN])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    ssize_t written = write(fd, frame, FRAME_LEN);
    int closed = close(fd);
    return written == FRAME_LEN && closed == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[2], "control") != 0 && strcmp(argv[2], "zero-fragment") != 0)) {
        fprintf(stderr, "usage: %s VALE_PORT control|zero-fragment EXPECTED_FILE\n", argv[0]);
        return 2;
    }
    uint8_t frame[FRAME_LEN];
    MakeFrame(frame);
    if (SaveFrame(argv[3], frame) != 0)
        return 2;
    struct nmport_d *port = nmport_open(argv[1]);
    if (port == NULL) {
        perror("nmport_open");
        return 2;
    }
    int split = strcmp(argv[2], "zero-fragment") == 0;
    struct netmap_ring *ring = NULL;
    for (int attempt = 0; attempt < 100 && ring == NULL; attempt++) {
        for (uint32_t id = port->first_tx_ring; id <= port->last_tx_ring; id++) {
            struct netmap_ring *candidate = NETMAP_TXRING(port->nifp, id);
            if (candidate->nr_buf_size >= FRAME_LEN && nm_ring_space(candidate) >= 1U + split) {
                ring = candidate;
                break;
            }
        }
        if (ring == NULL) {
            struct pollfd pfd = { .fd = port->fd, .events = POLLOUT };
            if (poll(&pfd, 1, 100) < 0 && errno != EINTR) {
                perror("poll");
                return 2;
            }
            if (ioctl(port->fd, NIOCTXSYNC, NULL) < 0) {
                perror("NIOCTXSYNC");
                return 2;
            }
        }
    }
    if (ring == NULL) {
        fprintf(stderr, "no TX ring with room for the test frame\n");
        return 2;
    }
    uint32_t i = ring->head;
    struct netmap_slot *slot = &ring->slot[i];
    if (split) {
        /* Do not write any data to the zero-length first slot. */
        slot->len = 0;
        slot->flags = NS_MOREFRAG;
        i = nm_ring_next(ring, i);
        slot = &ring->slot[i];
    }
    memcpy(NETMAP_BUF(ring, slot->buf_idx), frame, FRAME_LEN);
    slot->len = FRAME_LEN;
    slot->flags = NS_REPORT;
    ring->head = ring->cur = nm_ring_next(ring, i);
    if (ioctl(port->fd, NIOCTXSYNC, NULL) < 0) {
        perror("NIOCTXSYNC");
        return 2;
    }
    nmport_close(port);
    printf("submitted %s frame through VALE\n", argv[2]);
    return 0;
}
