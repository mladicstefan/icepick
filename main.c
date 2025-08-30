#include "pcap.h"
#include <stdio.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) != 0) {
        fprintf(stderr, "pcap init failed %s\n", errbuf);
        return -1;
    }

    if (list_interfaces(errbuf) < 0) {
        fprintf(stderr, "Not able to find interfaces %s\n", errbuf);
        return -2;
    }

    pcap_t *handle = create_handle("wlan0", errbuf);
    if (handle == NULL) {
        return -3;
    }

    start_capture(handle);
    pcap_close(handle);
    return 0;
}
