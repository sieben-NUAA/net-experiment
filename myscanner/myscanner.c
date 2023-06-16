#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#define MAX_HOSTS 100
#define MIN_PORT 1
#define MAX_PORT 65535

// 扫描指定主机和端口
void scan_host(const char *hostname, const char *ip, int port) {
    struct sockaddr_in addr;
    int sockfd;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    // 设置目标地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &(addr.sin_addr)) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return;
    }

    // 尝试连接
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        printf("Host: %s (%s)\n", hostname, ip);
        printf("  Port %d: Open\n", port);
    }

    close(sockfd);
}

int main() {
    char hostname[MAX_HOSTS][NI_MAXHOST];
    char ip[MAX_HOSTS][NI_MAXHOST];
    int num_hosts = 0;

    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    // 获取本地网络接口信息
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // 遍历网络接口列表
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        sa = (struct sockaddr_in *)ifa->ifa_addr;
        addr = inet_ntoa(sa->sin_addr);

        // 检查是否已经保存过该主机名
        int found = 0;
        for (int i = 0; i < num_hosts; i++) {
            if (strcmp(hostname[i], ifa->ifa_name) == 0) {
                found = 1;
                break;
            }
        }

        // 如果未保存过该主机名，则保存主机名和IP地址
        if (!found) {
            strncpy(hostname[num_hosts], ifa->ifa_name, NI_MAXHOST);
            strncpy(ip[num_hosts], addr, NI_MAXHOST);
            num_hosts++;
        }
    }

    freeifaddrs(ifaddr);

    // 扫描局域网内的主机
    printf("Scanning LAN...\n");
    printf("----------------\n");

    for (int i = 0; i < num_hosts; i++) {
        printf("Host: %s (%s)\n", hostname[i], ip[i]);

        for (int port = MIN_PORT; port <= MAX_PORT; port++) {
            scan_host(hostname[i], ip[i], port);
        }

        printf("----------------\n");
    }

    return 0;
}

