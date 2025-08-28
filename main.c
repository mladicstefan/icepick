#include <pcap/pcap.h>
#include <stdio.h>

int list_interfaces(char* errbuf)
{
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return -1;
    }

    pcap_if_t *dev;
    for (dev = alldevs; dev != NULL; dev= dev->next){
        printf("%s\n",dev->name);
        if (dev-> description){
            printf("Desc: %s\n",dev->description);
        }
        printf("%c\n", dev->flags);
    }
    pcap_freealldevs(alldevs);
    return 0;
}

void set_flags(pcap_t *handle)
{
    pcap_set_timeout(handle, 1000);
}

pcap_t *create_handle(char *device, char *errbuf)
{
    pcap_t *handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return NULL;
    }

    set_flags(handle);

    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    return handle;
}


int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) != 0){
        fprintf(stderr, "pcap init failed %s\n", errbuf);
        return -1;
    }

    if (list_interfaces(errbuf) < 0){
        fprintf(stderr, "Not able to find interfaces %s\n", errbuf);
        return -2;
    }
    pcap_t *handle = create_handle("lo", errbuf); //lo is for loopback, wlan1 would be for monitor mode
    if (handle == NULL){
        return -3;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;

    printf("Starting packet capture on lo...\n");
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue;  // Timeout, try again

        printf("Captured packet: %d bytes from %s\n", header->caplen, "lo");
        // TODO: Parse the packet data
    }

    pcap_close(handle);
    return 0;
}
