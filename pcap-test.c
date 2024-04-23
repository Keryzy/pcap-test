#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void _print(uint8_t* packet, int num){
    for(int i=0; i< num;i++){
        if(num == 4) // ip
            printf("%d ",packet[i]);
        else // mac, data
            printf("%02x ",packet[i]);
    }
    printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
        /* Get Ethernet header */
        struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet;

        if(ethernet_hdr->ether_type == 8 ){ // Check IP ( ETHERTYPE_IP == 8 )

            /* Get IP header */
            packet += sizeof(struct libnet_ethernet_hdr);
            struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;

            if(ipv4_hdr->ip_p == 6){ //Check TCP ( IPPROTO_TCP == 6 )
                /* Get TCP header */
                uint8_t iphdr_len = ipv4_hdr->ip_hl * 4;
                packet += iphdr_len;
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)packet;

                /* Get Packet Length */
                printf("%u bytes captured\n\n", header->caplen);

                /* src / dst mac */
                uint8_t* src_mac = ethernet_hdr->ether_shost;
                uint8_t* dst_mac = ethernet_hdr->ether_dhost;
                printf("Src_mac : ");
                _print(src_mac, 6);
                printf("Dst_mac : ");
                _print(dst_mac, 6);

                /* src / dst ip */
                uint8_t* src_ip = (uint8_t*)&ipv4_hdr->ip_src;
                uint8_t* dst_ip = (uint8_t*)&ipv4_hdr->ip_dst;
                printf("Src_ip : ");
                _print(src_ip, 4);
                printf("Dst_ip : ");
                _print(dst_ip, 4);

                /* src / dst port */
                uint16_t src_port = ntohs(tcp_hdr->th_sport);
                uint16_t dst_port = ntohs(tcp_hdr->th_dport);
                printf("Src_port : %d\n", src_port);
                printf("Dst_port : %d\n\n", dst_port);

                /* Get Payload(Data) hexadecimal value (Max 20byte) */
                uint8_t tcphdr_len = tcp_hdr->th_off * 4;
                packet += tcphdr_len;
                uint8_t* data = (uint8_t*)packet;
                uint16_t datalen = ntohs(ipv4_hdr->ip_len) - iphdr_len - tcphdr_len;
                uint16_t maxlen = datalen > 20 ? 20 : datalen;
                printf("Data : ");
                _print(data, maxlen);
            }
        }
	}

	pcap_close(pcap);
}
