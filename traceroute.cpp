#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#define MAX_HOPS 30
#define TIMEOUT_SEC 1

using namespace std;

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
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

void traceroute(const char *target) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
       if (sockfd < 0) {
        perror("Socket error");
        exit(1);
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target, &dest_addr.sin_addr);

    cout << "Traceroute to " << target << " with max hops " << MAX_HOPS << endl;

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct icmphdr icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = ICMP_ECHO;
        icmp_hdr.un.echo.id = getpid();
        icmp_hdr.un.echo.sequence = ttl;
        icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);
        struct timeval start, end;
        gettimeofday(&start, NULL);

        cout << "Setting TTL to " << ttl << endl;
        if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto error");
            continue;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        struct timeval timeout = {TIMEOUT_SEC, 0};

        cout << "Waiting for ICMP reply for TTL = " << ttl << endl;
        if (select(sockfd + 1, &readfds, NULL, NULL, &timeout) > 0) {
            char recv_buf[512];
            int bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_addr, &addr_len);
            if (bytes_received < 0) {
                perror("recvfrom error");
                continue;
            }

            gettimeofday(&end, NULL);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

            struct iphdr *ip_hdr = (struct iphdr *)recv_buf;
            struct icmphdr *icmp_hdr_reply = (struct icmphdr *)(recv_buf + (ip_hdr->ihl * 4));

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &recv_addr.sin_addr, ip_str, sizeof(ip_str));

            struct hostent *host = gethostbyaddr(&recv_addr.sin_addr, sizeof(recv_addr.sin_addr), AF_INET);

            cout << ttl << " \t " << ip_str;
            if (host) {
                cout << " (" << host->h_name << ")";
            }
            cout << " \t " << rtt << " ms" << endl;

            cout << "Received response from " << ip_str << ", type: " << (int)icmp_hdr_reply->type << endl;


            if (icmp_hdr_reply->type == ICMP_ECHOREPLY) {
                break;
            } else if (icmp_hdr_reply->type == ICMP_TIME_EXCEEDED) {
                continue;
            }
        } else {
            cout << ttl << " \t *" << endl;
        }
    }
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <IP/hostname>" << endl;
        return 1;
    }
    traceroute(argv[1]);
    return 0;
}

