#include <pcap/dlt.h>
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

    if (pcap_set_rfmon(handle, 1) != 0) {
        printf("Failed to set monitor mode: %s\n", pcap_geterr(handle));
    } else {
        printf("Monitor mode set successfully\n");
    }
    set_flags(handle);

    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    return handle;
}


void parse_radiotap_802_11(struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Raw packet dump (%d bytes):\n", header->caplen);

    // Hex dump format
    for (int i = 0; i < header->caplen; i++) {
        if (i % 16 == 0) printf("%04x: ", i);  // Address offset
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");   // New line every 16 bytes
    }
    if (header->caplen % 16 != 0) printf("\n"); // Final newline if needed

    printf("\n");
}

void parse_packet(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet)
{
    int datalink = pcap_datalink(handle);
    switch (datalink)
    {
        case DLT_IEEE802_11_RADIO: //127, for parsing in monitor mode
            parse_radiotap_802_11(header,packet);
            printf("Passing Monitor Mode...");
            break;
        case DLT_NULL:
            printf("Parsing loopback");
            break;
        case DLT_EN10MB: // 1 - Ethernet format
            printf("Parsing Ethernet packet\n");
            break;
        default:
        printf("Unknown datalink type: %c\n", datalink);
    }
}

void start_capture(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;

    printf("Starting packet capture...\n");
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue;  // Timeout, try again

        printf("Captured packet: %d bytes \n", header->caplen);

        parse_packet(handle, header, packet);
    }
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
    pcap_t *handle = create_handle("wlan0", errbuf); //lo is for loopback, wlan1 (or whatever ur monitor mode adapter is) would be for monitor mode
    if (handle == NULL){
        return -3;
    }
    start_capture(handle);

    pcap_close(handle);
    return 0;
}
