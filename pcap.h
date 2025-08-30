#pragma once
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <sys/types.h>

/**
 * Radiotap header structure - Variable-length metadata for 802.11 frames
 *
 * Radiotap is a standard format that wireless capture tools use to prepend
 * radio metadata to raw 802.11 frames. Unlike most network protocols,
 * radiotap uses little-endian byte order for all multi-byte fields.
 *
 * CRITICAL: Only the first 8 bytes are fixed-size. Everything after the
 * 'present' field is variable and determined by the present bitmap.
 *
 * Wire format vs libpcap metadata:
 * - This struct represents actual packet bytes on the wire
 * - pcap_pkthdr contains libpcap's capture metadata (timestamps, lengths)
 * - These are completely separate - don't confuse wire format with capture metadata
 */
struct radiotap_header {
    uint8_t version;    // Radiotap version (always 0)
    uint8_t pad;        // Padding for alignment
    uint16_t len;       // Total radiotap header length (LITTLE-ENDIAN!)
    uint32_t present;   // Bitmap indicating which fields follow (LITTLE-ENDIAN!)
} __attribute__((packed));

/**
 * Present field bitmap explanation:
 *
 * The 'present' field is a 32-bit bitmap where each bit indicates whether
 * a specific radiotap field is included after this header. For example:
 * - Bit 0: TSFT (timestamp)
 * - Bit 2: Rate
 * - Bit 5: Antenna signal strength (dBm)
 * - Bit 31: Extension bit - if set, another present field follows
 *
 * VARIABLE SIZE WARNING: If bit 31 is set, you have multiple present fields
 * chained together. You must parse all present fields before knowing where
 * the variable radiotap data starts.
 */

/**
 * Discovers and prints all available network interfaces on the system.
 * Useful for identifying capture targets before creating handles.
 * @param errbuf Buffer to store error messages (PCAP_ERRBUF_SIZE)
 * @return 0 on success, -1 on failure
 */
int list_interfaces(char *errbuf);

/**
 * Configures pcap handle for monitor mode capture with non-blocking I/O.
 * Sets immediate mode (no buffering), monitor mode (if wireless), and
 * non-blocking mode for integration with event loops.
 * @param handle Active pcap handle to configure
 * @param errbuf Buffer to store error messages
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
 * Prints human-readable timestamp from libpcap's capture metadata.
 * NOTE: This is when libpcap captured the packet, NOT any network timing.
 * Formats as YYYY-MM-DD HH:MM:SS.microseconds
 * @param header Packet header containing libpcap's timestamp data
 */
void print_packet_timestamps(struct pcap_pkthdr *header);

/**
 * Parses 802.11 wireless frames with radiotap headers (DLT_IEEE802_11_RADIO).
 *
 * Handles the variable-length radiotap header by reading the length field
 * and skipping to the actual 802.11 frame. Currently displays hex dump
 * of the 802.11 portion only (radiotap metadata parsing not implemented).
 *
 * @param header libpcap packet metadata (capture time, lengths)
 * @param packet Raw packet bytes starting with radiotap header
 */
void parse_radiotap_802_11(struct pcap_pkthdr *header, const u_char *packet);

/**
 * Main packet dispatcher based on datalink layer type.
 * Routes packets to appropriate parsers based on pcap's detected link type.
 * Currently supports:
 * - DLT_IEEE802_11_RADIO: 802.11 with radiotap (monitor mode)
 * - DLT_EN10MB: Ethernet (testing/development)
 * - DLT_NULL: Loopback (testing/development)
 *
 * @param handle pcap handle (used to determine datalink type)
 * @param header libpcap packet metadata
 * @param packet Raw packet data buffer
 */
void parse_packet(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet);

/**
 * Main non-blocking capture loop using pcap_next_ex().
 * Continuously processes packets until interrupted or error occurs.
 * TODO: Integrate with epoll/event loop to avoid busy-waiting on timeouts.
 *
 * @param handle Active pcap handle for packet capture
 */
void start_capture(pcap_t *handle);
