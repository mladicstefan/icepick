#include "pcap.h"
#include "lib/corelib/threadpool.h"
#include <string.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

int list_interfaces(char *errbuf)
{
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return -1;
    }
    pcap_if_t *dev;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%s\n", dev->name);
        if (dev->description) {
            printf("Desc: %s\n", dev->description);
        }
        printf("%u\n", dev->flags);
    }
    pcap_freealldevs(alldevs);
    return 0;
}

void parse_packet_wrapper(void *arg) {
    packet_work_t *work = (packet_work_t *)arg;
    parse_packet(work->handle, work->header, work->packet);
    free((void*)work->packet);
    free(work->header);
    free(work);
}

void set_flags(pcap_t *handle, char *errbuf)
{
    pcap_set_immediate_mode(handle, 1); // Packets get sent as soon as they arrive, no buffering. Otherwise would need to set timeout pcap_set_timeout
    if (pcap_set_rfmon(handle, 1) != 0) {
        printf("Failed to set monitor mode: %s\n", pcap_geterr(handle));
    } else {
        printf("Monitor mode set successfully\n");
    }
    pcap_setnonblock(handle, 1, errbuf);
}

pcap_t *create_handle(char *device, char *errbuf)
{
    pcap_t *handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return NULL;
    }

    set_flags(handle, errbuf);

    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    return handle;
}

void print_packet_timestamps(struct pcap_pkthdr *header)
{
    struct tm *tm_info = localtime(&header->ts.tv_sec);
    printf("Captured: %04d-%02d-%02d %02d:%02d:%02d.%06ld\n",
           tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
           tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
           header->ts.tv_usec);
}

void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void parse_radiotap_802_11(struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Raw packet dump (%d bytes):\n", header->caplen);
    print_packet_timestamps(header);

    // only the radiotap header is fixed size, so we can only cast this part before viewing the bitmap (present)
    const struct radiotap_header *rt_hdr = (const struct radiotap_header*) packet;

    // handle endianness
    // rt_hdr->len= le16toh(rt_hdr->len); //little endian to 16 host
    // rt_hdr->present = le32toh(rt_hdr->present); //same
    // NOTE: This is commented out since for the pcap API to work packet needs to be const which means
    // that rt_hdr is also const, so i cannot assign rt_hdr->len to match host endiannes :(
    uint16_t rt_len = le16toh(rt_hdr->len);
    uint32_t present = le32toh(rt_hdr->present);

    printf("Header: version=%d, length=%d, present=0x%08x\n",
            rt_hdr->version, rt_len, present);

    //might seem confusing, pointer isn't const, it's data is though
    //this gives us radiotap header and frame lenght
    const u_char *fieldptr = packet + rt_len;

    // const u_char *end = packet + header->caplen; might need to be used idk

    uint32_t frame_len = header->caplen - rt_len;
    printf("Frame lenght:%d\n", frame_len);

    const struct ieee802_11_frame *frame = (const struct ieee802_11_frame*) fieldptr;
    uint16_t fc = le16toh(frame->frame_control);

    uint8_t frame_type = (fc >> 2) & 0x3;
    uint8_t frame_subtype = (fc >> 4) & 0xF;
    //todo, do something with this something biiiig

    uint16_t duration = le16toh(frame->duration);
    uint16_t seq_ctrl = le16toh(frame->seq_ctrl);

    uint16_t seq_num = (seq_ctrl >> 4) & 0xFFF;
    uint8_t frag_num = seq_ctrl & 0xF;

    printf("Frame type=%d, subtype=%d, duration=%d, seq=%d, frag=%d\n",
           frame_type, frame_subtype, duration, seq_num, frag_num);
    // Decode ToDS/FromDS to interpret addressing correctly
    uint8_t to_ds = (fc >> 8) & 0x1;
    uint8_t from_ds = (fc >> 9) & 0x1;

    printf("Immediate Receiver: "); print_mac(frame->addr1); printf("\n");
    printf("Immediate Transmitter: "); print_mac(frame->addr2); printf("\n");

    if (frame_type == 0) {
        printf("BSSID: "); print_mac(frame->addr3); printf("\n");
    } else if (frame_type == 2) {
        if (to_ds && !from_ds) {
            printf("Final Destination: "); print_mac(frame->addr3); printf("\n");
        } else if (!to_ds && from_ds) {
            printf("Original Source: "); print_mac(frame->addr3); printf("\n");
        }
    }
}

void parse_packet(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet)
{
    int datalink = pcap_datalink(handle);
    switch (datalink) {
        case DLT_IEEE802_11_RADIO: //127, for parsing in monitor mode
            parse_radiotap_802_11(header, packet);
            break;
        case DLT_NULL:
            printf("Parsing loopback");
            break;
        case DLT_EN10MB: // 1 - Ethernet format
            printf("Parsing Ethernet packet\n");
            break;
        default:
            printf("Unknown datalink type: %d\n", datalink);
    }
}

void start_capture(pcap_t *handle, threadpool_t *pool)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;
    printf("Starting packet capture...\n");

    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue;  // Timeout, try again
        assert(header->caplen > 0);
        packet_work_t *work = malloc(sizeof(packet_work_t));
        work->handle = handle;

        work->header = malloc(sizeof(struct pcap_pkthdr));
        memcpy(work->header, header, sizeof(struct pcap_pkthdr));

        work->packet = malloc(header->caplen);
        memcpy((void*)work->packet, packet, header->caplen);

        threadpool_add(pool, parse_packet_wrapper, work);
    }
}
