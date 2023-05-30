#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#define PACKET_SIZE 64
#define MAX_HOPS 30
#define MAX_RETRIES 3
#define TIMEOUT 1

typedef struct {
    struct timeval start_time;
    struct sockaddr_in addr;
    int tries;
} icmp_packet;

void print_ip_address(struct in_addr *ip_address) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_address, ip_str, sizeof(ip_str));
    printf("%s ", ip_str);
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void send_icmp_packet(int sockfd, struct sockaddr_in *dest_addr, int seq_num) {
    icmp_packet packet;
    struct icmp *icmp_hdr;
    char packet_buffer[PACKET_SIZE];
    int bytes_sent;

    memset(&packet, 0, sizeof(packet));

    packet.addr = *dest_addr;
    packet.tries = 1;

    gettimeofday(&packet.start_time, NULL);

    icmp_hdr = (struct icmp *)packet_buffer;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_seq = seq_num;
    icmp_hdr->icmp_id = getpid();
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum(packet_buffer, PACKET_SIZE);

    bytes_sent = sendto(sockfd, packet_buffer, PACKET_SIZE, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr));

    if (bytes_sent < 0) {
        perror("sendto");
        exit(1);
    }
}

int receive_icmp_reply(int sockfd, struct sockaddr_in *dest_addr, struct timeval *start_time) {
    char packet_buffer[PACKET_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    int bytes_received, ip_hdr_len, icmp_hdr_len, icmp_type, icmp_code;
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    struct timeval end_time;

    bytes_received = recvfrom(sockfd, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

    if (bytes_received < 0) {
        perror("recvfrom");
        exit(1);
    }

    gettimeofday(&end_time, NULL);

    ip_hdr = (struct ip *)packet_buffer;
    ip_hdr_len = ip_hdr->ip_hl << 2;
    icmp_hdr = (struct icmp *)(packet_buffer + ip_hdr_len);
    icmp_hdr_len = sizeof(struct icmp);

    icmp_type = icmp_hdr->icmp_type;
    icmp_code = icmp_hdr->icmp_code;

    if (icmp_type == ICMP_TIME_EXCEEDED && icmp_code == ICMP_EXC_TTL) {
        struct ip *orig_ip_hdr = (struct ip *)(packet_buffer + ip_hdr_len + icmp_hdr_len);
        struct icmp *orig_icmp_hdr = (struct icmp *)(packet_buffer + ip_hdr_len + icmp_hdr_len + (orig_ip_hdr->ip_hl << 2));

        if (orig_icmp_hdr->icmp_id == getpid()) {
            print_ip_address(&recv_addr.sin_addr);
            return 0;
        }
    } else if (icmp_type == ICMP_ECHOREPLY) {
        if (icmp_hdr->icmp_id == getpid()) {
            print_ip_address(&recv_addr.sin_addr);

            if (start_time != NULL) {
                long elapsed_time = (end_time.tv_sec - start_time->tv_sec) * 1000 + (end_time.tv_usec - start_time->tv_usec) / 1000;
                printf("%ldms ", elapsed_time);
            }

            return 1;
        }
    }

    return -1;
}

void trace_route(const char *host) {
    struct hostent *host_entry;
    struct sockaddr_in dest_addr;
    int sockfd, seq_num, retries, i;
    struct timeval timeout;
    fd_set read_set;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    dest_addr.sin_family = AF_INET;
    host_entry = gethostbyname(host);

    if (host_entry == NULL) {
        printf("Could not resolve '%s'\n", host);
        exit(1);
    }

    memcpy(&dest_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);

    printf("通过最多 %d 个跃点跟踪到 %s [%s] 的路由:\n\n", MAX_HOPS, host, inet_ntoa(dest_addr.sin_addr));

    for (seq_num = 1; seq_num <= MAX_HOPS; seq_num++) {
        printf("%2d ", seq_num);

        for (retries = 0; retries < MAX_RETRIES; retries++) {
            send_icmp_packet(sockfd, &dest_addr, seq_num);
        }

        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        timeout.tv_sec = TIMEOUT;
        timeout.tv_usec = 0;

        if (select(sockfd + 1, &read_set, NULL, NULL, &timeout) > 0) {
            if (FD_ISSET(sockfd, &read_set)) {
                if (receive_icmp_reply(sockfd, &dest_addr, &timeout) == 1) {
                    printf("\n");
                    close(sockfd);
                    return;
                }
            }
        } else {
            printf("*\n");
        }
    }

    printf("\n");
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <host>\n", argv[0]);
        return 1;
    }

    trace_route(argv[1]);

    return 0;
}

