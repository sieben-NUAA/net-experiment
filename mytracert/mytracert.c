#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define PACKET_SIZE 64
#define MAX_WAIT_TIME 5
#define MAX_NO_PACKETS 3
#define MAX_HOPS 30

// 计算校验和
unsigned short calcChecksum(unsigned short *addr, int len)
{
    unsigned int sum = 0;
    unsigned short answer = 0;
    unsigned short *w = addr;
    int nleft = len;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

// 发送ICMP请求
int sendPingRequest(int sockfd, struct sockaddr_in *dest_addr, int packet_size, int ttl)
{
    struct icmp *icmp_packet;
    char send_packet[PACKET_SIZE];
    int packet_len;

    icmp_packet = (struct icmp *)send_packet;
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0; // 询问报文  
    icmp_packet->icmp_id = getpid();
    icmp_packet->icmp_seq = 0;
    memset(icmp_packet->icmp_data, 0xa5, packet_size);
    gettimeofday((struct timeval *)icmp_packet->icmp_data, NULL);

    packet_len = 8 + packet_size;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_cksum = calcChecksum((unsigned short *)icmp_packet, packet_len);

    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) == -1) {
        perror("setsockopt error");
        return -1;
    }

    if (sendto(sockfd, send_packet, packet_len, 0, 
        (struct sockaddr *)dest_addr, sizeof(struct sockaddr)) == -1) {
        perror("sendto error");
        return -1;
    }

    return 0;
}

// 接收ICMP应答
int receivePingResponse(int sockfd, int ttl)
{
    char recv_packet[PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t from_len;
    int packet_len;

    while (1) {
        memset(recv_packet, 0, sizeof(recv_packet));
        from_len = sizeof(from);

        if ((packet_len = recvfrom(sockfd, recv_packet, sizeof(recv_packet), 0, 
                    (struct sockaddr *)&from, &from_len)) == -1) {
            perror("recvfrom error");
            return -1;
        }

        // 解析ICMP应答
        struct ip *ip_packet = (struct ip *)recv_packet;
        struct icmp *icmp_packet = (struct icmp *)(recv_packet + (ip_packet->ip_hl << 2));

        if (icmp_packet->icmp_type == ICMP_TIME_EXCEEDED && icmp_packet->icmp_code == ICMP_EXC_TTL
            && ip_packet->ip_ttl <= MAX_HOPS) {
            struct timeval *st = (struct timeval *)(icmp_packet->icmp_data + 8);

            double rtt = st->tv_sec * 1000.0 + (st->tv_usec / 1000.0);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(from.sin_addr), addr_str, INET_ADDRSTRLEN);

            printf("%2d   %.3f ms   %.3f ms   %.3f ms   %s\n", ttl, rtt, rtt, rtt, addr_str);
            break;
        }
        else if (icmp_packet->icmp_type == ICMP_ECHOREPLY) {
            struct timeval *st = (struct timeval *)(icmp_packet->icmp_data);
            struct timeval ct;
            gettimeofday(&ct, NULL);

            double rtt = (ct.tv_sec - st->tv_sec) * 1000.0 + (ct.tv_usec - st->tv_usec) / 1000.0;
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(from.sin_addr), addr_str, INET_ADDRSTRLEN);

            printf("%2d   %.3f ms   %.3f ms   %.3f ms   %s\n", ttl, rtt, rtt, rtt, addr_str);
            return 1;
        }
    }

    return 0;
}

// 执行traceroute
void traceroute(const char *hostname)
{
    struct hostent *host;
    struct sockaddr_in dest_addr;
    int sockfd;
    int ttl;

    if ((host = gethostbyname(hostname)) == NULL) {
        printf("Unable to resolve hostname.\n");
        return;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(0);
    memcpy(&(dest_addr.sin_addr), host->h_addr, host->h_length);

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket error");
        return;
    }

    printf("通过最多 %d 个跃点跟踪到 %s [%s] 的路由:\n\n", MAX_HOPS, hostname, inet_ntoa(dest_addr.sin_addr));

    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        printf("%2d   ", ttl);

        // 发送3个ICMP请求
        for (int i = 0; i < MAX_NO_PACKETS; i++) {
            if (sendPingRequest(sockfd, &dest_addr, PACKET_SIZE, ttl) == -1) {
                close(sockfd);
                return;
            }
        }

        // 接收ICMP应答
        int result = receivePingResponse(sockfd, ttl);
        if (result == -1) {
            close(sockfd);
            return;
        }
        else if (result == 1) {
            break;
        }
    }

    close(sockfd);
    printf("\n跟踪完成。\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
    	printf("error: mytracert dst_addr\n");
		exit(1);
	}

	// 解析命令行参数
	char *dest_ip = argv[1];
    traceroute(dest_ip);

    return 0;
}

