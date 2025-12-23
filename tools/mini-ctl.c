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

    // 打开密钥文件并读取密钥
    key_fd = open(keyfile, O_RDONLY);
    if (key_fd == -1) {
        perror("open keyfile");
        return;
    }
    read(key_fd, key, 32);  // 假设密钥长度为32字节
    close(key_fd);

    // 创建Netlink套接字
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MGMT);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // 配置Netlink目标地址
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // 分配Netlink消息结构
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(key)));
    memset(nlh, 0, NLMSG_SPACE(sizeof(key)));

    nlh->nlmsg_len = NLMSG_SPACE(sizeof(key));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_type = MINI_CTL_SET_KEY;

    memcpy(NLMSG_DATA(nlh), key, sizeof(key));

    // 发送Netlink消息到内核
    if (sendto(sock_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
    }

    free(nlh);
    close(sock_fd);
}

int main(int argc, char **argv)
{
    const char *key_path;

    // 确保传递了命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key-file>\n", argv[0]);
        return 1;
    }

    // 获取命令行参数中的密钥文件路径
    key_path = argv[1];

    // 调用 send_key 函数发送密钥到内核模块
    send_key(key_path);

    return 0;
}
