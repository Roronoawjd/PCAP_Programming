// 컴파일 gcc -o tcp_sniff tcp_sniff.c -lpcap

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 이더넷 헤더 추출
    struct ethheader *eth = ((struct ethheader *)packet);

    // IP 패킷만 캡쳐 IP Type은 0x0800
    if (ntohs(eth->ether_type) == 0x0800) {

    // IP 헤더 추출(패킷 길이 + 이더넷 길이)
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

    // TCP 헤더 추출(패킷 길이 + 이더넷 길이 + ip헤더 길이)
    struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));
    
    // TCP 헤더 이후의 메시지 시작 위치 계산(패킷 길이 + 이더넷 길이 + ip헤더 길이 + tcp 헤더 길이)
    const u_char *message = packet + sizeof(struct ethheader) + (ip->iph_ihl << 2) + (TH_OFF(tcp) * 4);


    // 4계층 프로토콜 종류 확인
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("Protocol 종류: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocol 종류: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocol 종류: ICMP\n");
            break;
        default:
            printf("Protocol 종류: others\n");
            break;
    }

    // 송신자와 수신자 IP 주소 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));    

    // 송신자와 수신자 포트 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    // 메시지 출력 (최대 128바이트까지)
    int max_message_length = 128;
    int data_length = ntohs(ip->iph_len) - (ip->iph_ihl << 2) - (TH_OFF(tcp) * 4);

    if (data_length > 0) {
        printf("Message Data:\n");
        for (int i = 0; i < data_length && i < max_message_length; i++) {
            printf("%02x ", message[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    }
    printf("\n");

  }

}

int main() {
    char dev[] = "ens33";  // 네트워크 장치 이름
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 받음
    bpf_u_int32 net;

    // 네트워크 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // 패킷 스니핑 필터 적용
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
    }

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    // 핸들 닫기
    pcap_close(handle);

    return 0;
}
