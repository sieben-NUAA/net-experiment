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
    struct icmphdr icmp;
    char packet[PACKET_SIZE];
    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = getpid();
    icmp.un.echo.sequence = seq;
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &icmp, sizeof(icmp));
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
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
    int ttl, seq, sockfd,done = 0;
    struct sockaddr_in addr;

    for (ttl = 1; ttl <= MAX_HOPS && !done; ttl++) {
        printf("%2d  ", ttl);
        fflush(stdout);
        for (seq = 0; seq < 3 && !done; seq++) {
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
			//printf(" ret = %d ", ret);

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
				printf("\n");
				continue;
			}
			printf("%-15s", ipstr1); 
            if (strcmp(ipstr, ipstr1) == 0) {
				//printf("dddd");
                done = 1;
            }
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
