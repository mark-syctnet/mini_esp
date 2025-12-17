#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_MGMT 30
#define MINI_CTL_SET_KEY 1

void send_key(const char *keyfile)
{
    struct nlmsghdr *nlh;
    struct sockaddr_nl sa;
    int sock_fd;
    int key_fd;
    unsigned char key[32];

    key_fd = open(keyfile, O_RDONLY);
    if (key_fd == -1) {
        perror("open keyfile");
        return;
    }
    read(key_fd, key, 32);
    close(key_fd);

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MGMT);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(key)));
    memset(nlh, 0, NLMSG_SPACE(sizeof(key)));

    nlh->nlmsg_len = NLMSG_SPACE(sizeof(key));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_type = MINI_CTL_SET_KEY;

    memcpy(NLMSG_DATA(nlh), key, sizeof(key));

    if (sendto(sock_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    }

    free(nlh);
    close(sock_fd);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key-file>\n", argv[0]);
        return 1;
    }

    send_key(argv[1]);
    return 0;
}
