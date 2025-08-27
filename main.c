#include <pcap/pcap.h>
#include <stdio.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) != 0){
        fprintf(stderr, "pcap init failed %s\n", errbuf);
        return -1;
    }
    return 0;
}
