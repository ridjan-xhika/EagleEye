#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        printf("Captured packet:\n");
        printf("From: %s\n", src_ip);
        printf("To:   %s\n", dst_ip);
        int ip_header_len = ip_header->ip_hl * 4;
        const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len;
        int payload_len = header->len - (sizeof(struct ether_header) + ip_header_len);
        printf("Payload (%d bytes): ", payload_len > 16 ? 16 : payload_len);
        for (int i = 0; i < (payload_len > 16 ? 16 : payload_len); i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int device = pcap_findalldevs(&alldevs, errbuf);

    if (device == -1) {
        fprintf(stderr, "Could not find devices: %s\n", errbuf);
        return 1;
    }
    pcap_t *handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
