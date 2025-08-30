#pragma once

#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <sys/types.h>

/**
 * Discovers and prints all available network interfaces on the system.
 * Useful for identifying capture targets before creating handles.
 * @param errbuf Buffer to store error messages (PCAP_ERRBUF_SIZE)
 * @return 0 on success, -1 on failure
 */
int list_interfaces(char *errbuf);

/**
 * Configures pcap handle with standard timeout settings.
 * Currently sets 1000ms timeout for packet capture operations.
 * @param handle Active pcap handle to configure
 */
void set_flags(pcap_t *handle, char *errbuf);

/**
 * Creates and activates a pcap handle for the specified device.
 * Attempts to enable monitor mode for wireless interfaces.
 * @param device Network interface name (e.g., "wlan0", "eth0")
 * @param errbuf Buffer to store error messages (PCAP_ERRBUF_SIZE)
 * @return Activated pcap handle on success, NULL on failure
 */
pcap_t *create_handle(char *device, char *errbuf);

/**
 * Prints human-readable timestamp from packet header.
 * Formats as YYYY-MM-DD HH:MM:SS.microseconds
 * @param header Packet header containing timestamp data
 */
void print_packet_timestamps(struct pcap_pkthdr *header);

/**
 * Parses and displays 802.11 packets with radiotap headers.
 * Outputs hex dump and timestamp information for wireless packets.
 * @param header Packet header with length and timestamp
 * @param packet Raw packet data buffer
 */
void parse_radiotap_802_11(struct pcap_pkthdr *header, const u_char *packet);

/**
 * Main packet parser that dispatches based on datalink type.
 * Handles different link layer protocols (802.11,Ethernet, loopback). NOTE: ETH and lo are for testing
 * @param handle pcap handle (used to determine datalink type)
 * @param header Packet header with metadata
 * @param packet Raw packet data buffer
 */
void parse_packet(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet);

/**
 * Main capture loop that processes packets until interrupted.
 * Continuously captures and parses packets from the given handle.
 * @param handle Active pcap handle for packet capture
 */
void start_capture(pcap_t *handle);
