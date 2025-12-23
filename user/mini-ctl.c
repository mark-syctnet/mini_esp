#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#define MINI_NL_FAMILY 31
#define KEYLEN 32

struct mini_nl_sa {
    uint32_t mark;
    uint32_t peer_ip;
    uint16_t udp_port;
    unsigned char key[KEYLEN];
};

static void hex2bin(const char *hex, unsigned char *out)
{
    for (int i = 0; i < KEYLEN; i++)
        sscanf(hex + 2*i, "%2hhx", &out[i]);
}

int main(int argc, char **argv)
{
    if (argc != 6 || strcmp(argv[1], "add")) {
        fprintf(stderr, "usage: %s add <mark> <peer_ip> <udp_port> <hexkey>\n", argv[0]);
        return 1;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));

    struct {
        struct nlmsghdr nlh;
        struct mini_nl_sa sa;
    } msg = {0};

    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.sa));
    msg.sa.mark = strtoul(argv[2], NULL, 0);
    inet_pton(AF_INET, argv[3], &msg.sa.peer_ip);
    msg.sa.udp_port = htons(atoi(argv[4]));
    hex2bin(argv[5], msg.sa.key);

    struct sockaddr_nl kern = { .nl_family = AF_NETLINK, .nl_pid = 0 };
    sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr *)&kern, sizeof(kern));
    close(fd);
    return 0;
}
