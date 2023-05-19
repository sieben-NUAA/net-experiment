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
int sendPingRequest(int sockfd, struct sockaddr_in *dest_addr, int packet_size, int seq)
{
    struct icmp *icmp_packet;
    char send_packet[PACKET_SIZE];
    int packet_len;

    icmp_packet = (struct icmp *)send_packet;
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0; // 询问报文  
    icmp_packet->icmp_id = getpid();
    icmp_packet->icmp_seq = seq;
    memset(icmp_packet->icmp_data, 0xa5, packet_size);
    gettimeofday((struct timeval *)icmp_packet->icmp_data, NULL);

    packet_len = 8 + packet_size;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_cksum = calcChecksum((unsigned short *)icmp_packet, packet_len);

    if (sendto(sockfd, send_packet, packet_len, 0, 
		(struct sockaddr *)dest_addr, sizeof(struct sockaddr)) == -1) {
        perror("sendto error");
        return -1;
    }

    return 0;
}

// 接收ICMP应答
int receivePingResponse(int sockfd, int seq)
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
        // printf("Received ICMP response from: %s\n", inet_ntoa(from.sin_addr));

        // 解析ICMP应答
        struct ip *ip_packet = (struct ip *)recv_packet;
        struct icmp *icmp_packet = (struct icmp *)(recv_packet + (ip_packet->ip_hl << 2));

        if (icmp_packet->icmp_type == ICMP_ECHOREPLY && icmp_packet->icmp_id == getpid()
			&& icmp_packet->icmp_seq == seq) {
	    struct timeval *st = (struct timeval *)icmp_packet->icmp_data;
	    struct timeval ct;
	    gettimeofday(&ct, NULL);

	    double rtt = (ct.tv_sec - st->tv_sec) * 1000.0 + (ct.tv_usec - st->tv_usec) / 1000.0;
            printf("%d bytes from %s: icmp_seq=%d time=%.2fms ttl=%d\n",
           	packet_len, inet_ntoa(from.sin_addr), seq, rtt, ip_packet->ip_ttl);
	    // printf("ICMP response received.\n");
            break;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct hostent *host;
    int packet_size = PACKET_SIZE;
    int count = MAX_NO_PACKETS;

    if (argc < 3) {
        printf("error: myping dst_addr [-l package_size] [-n count]\n");
    	exit(1);
    }

    // 解析命令行参数
    char *dest_ip = argv[1];
    int i;
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            if (i + 1 < argc) {
                packet_size = atoi(argv[i + 1]);
                i++;
            }
        } else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 < argc) {
                count = atoi(argv[i + 1]);
                i++;
            }
        }
    }

    // 创建socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket error");
        exit(1);
    }

    // 设置目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &(dest_addr.sin_addr)) <= 0) {
        host = gethostbyname(dest_ip);
        if (host == NULL) {
            perror("gethostbyname error");
            exit(1);
        }
        memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
    }

    // 发送PING请求并接收应答
    int sent_packets = 0;
    int seq = 1;
    while (sent_packets < count) {
        if (sendPingRequest(sockfd, &dest_addr, packet_size, seq) == -1) {
            exit(1);
        }

        if (receivePingResponse(sockfd, seq) == -1) {
            exit(1);
        }

        sent_packets++;
	seq++;
        sleep(1);  // 1秒钟的延迟
    }

    // 关闭socket
    close(sockfd);

    return 0;
}

