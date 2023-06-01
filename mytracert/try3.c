#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>

#define MAX_HOPS  64
#define PACKET_SIZE  64
#define TIMEOUT  1

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

struct addrinfo* resolve_host(const char* host) 
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    int status = getaddrinfo(host, NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return NULL;
    }
    return res;
}

int create_socket(int ttl) 
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket error");
        return -1;
    }
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt error");
        close(sockfd);
        return -1;
    }
    struct timeval timeout = {TIMEOUT, 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt error");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int send_icmp_request(int sockfd, const struct sockaddr_in* addr, int seq) 
{
	struct icmp *icmp_packet;
    char send_packet[PACKET_SIZE];
    int packet_len;

    icmp_packet = (struct icmp *)send_packet;
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0; // 询问报文  
    icmp_packet->icmp_id = getpid();
    icmp_packet->icmp_seq = seq;
    memset(icmp_packet->icmp_data, 0xa5, PACKET_SIZE);
    gettimeofday((struct timeval *)icmp_packet->icmp_data, NULL);

    packet_len = 8 + PACKET_SIZE;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_cksum = calcChecksum((unsigned short *)icmp_packet, packet_len);

    if (sendto(sockfd, send_packet, packet_len, 0, 
		(struct sockaddr *)addr, sizeof(struct sockaddr)) == -1) {
        perror("sendto error");
        return -1;
    }
    return 0;
}

int recv_icmp_reply(int sockfd, struct sockaddr_in* from, struct timeval *start_time) 
{
    char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    socklen_t fromlen = sizeof(*from);
	struct timeval end_time;
	
    int n = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)from, &fromlen);
	gettimeofday(&end_time, NULL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
			printf(" *          ");
            return 2;
        } else {
            perror("recvfrom error");
            return -1;
        }
    }
    struct iphdr *iph = (struct iphdr *)packet;
    struct icmphdr *icmph = (struct icmphdr *)(packet + (iph->ihl << 2));
    if (icmph->type == ICMP_ECHOREPLY) {
		double elapsed_time = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + (end_time.tv_usec - start_time->tv_usec) / 1000.0;
		printf(" %fms ", elapsed_time);        
		return 1;
    } else if (icmph->type == ICMP_TIME_EXCEEDED) {
		double elapsed_time = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + (end_time.tv_usec - start_time->tv_usec) / 1000.0;
		printf(" %fms ", elapsed_time);
        return 0;
    } else {
		printf(" *          ");
        return -1;
    }
}

void format_addr(const struct sockaddr_in* addr, char* buffer, size_t size) {
    inet_ntop(AF_INET, &addr->sin_addr, buffer, size);
	// printf(" buffer: %s", buffer);
}

void tracert(const char* host) {
    struct addrinfo* res = resolve_host(host);
    if (res == NULL) {
        return;
    }
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(res->ai_family, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
    printf("Tracing route to %s [%s] over a maximum of %d hops:\n", host, ipstr, MAX_HOPS);
    int ttl, seq, sockfd, done = 0;
    struct sockaddr_in addr;

    for (ttl = 1; ttl <= MAX_HOPS && !done; ttl++) {
        printf("%2d  ", ttl);
        fflush(stdout);
        for (seq = 0; seq < 3; seq++) {
            sockfd = create_socket(ttl);
            if (sockfd < 0) {
                return;
            }
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
            addr.sin_port = htons(0);
	
            if (send_icmp_request(sockfd, &addr, seq) < 0) {
                close(sockfd);
                continue;
            }

			struct timeval tv;
			gettimeofday(&tv, NULL);
			int ret = recv_icmp_reply(sockfd, &addr, &tv);
			// printf(" ret = %d ", ret);

            if (ret < 0) {
                close(sockfd);
                continue;
            }

            char ipstr1[INET6_ADDRSTRLEN];
            format_addr(&addr, ipstr1, sizeof(ipstr1));
			
            if (ret == 2) continue;
			else if (ret == 0 && seq == 2) {
				printf("%-15s", ipstr1); 
				continue;
			}
			else if (ret == 0) continue;
			else if (seq == 2) {
				if (done) {
					printf("%-15s", ipstr1); 
					break;
				}
				printf("\n");
				continue;
			}
			// printf(" seq = %d ", seq);
			if (seq == 2)
				printf("%-15s", ipstr1); 
            if (strcmp(ipstr, ipstr1) == 0) {
                done = 1;
            }
			// if (done & seq == 2) break;
            close(sockfd);
        }
        printf("\n");
    }
    freeaddrinfo(res);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <host>\n", argv[0]);
        return 1;
    }
    // 解析命令行参数
    char *dest_ip = argv[1];
	tracert(dest_ip);
	return 0;
}
