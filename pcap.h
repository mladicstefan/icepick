#pragma once

#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include "lib/corelib/threadpool.h"
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

struct radiotap_header {
    uint8_t version;    // Radiotap version (always 0)
    uint8_t pad;        // Padding for alignment
    uint16_t len;       // Total radiotap header length (LITTLE-ENDIAN!)
    uint32_t present;   // Bitmap indicating which fields follow (LITTLE-ENDIAN!)
} __attribute__((packed));

/**
 * IEEE 802.11 frame header structure - Fixed addressing and control fields
 *
 * Standard 802.11 frame format used by all wireless devices. Contains addressing
 * information and frame control metadata that's always present regardless of
 * frame type (management, control, or data).

 * ToDS/FromDS bit interpretation for traffic direction analysis:
 *
 * These bits in frame_control determine wireless traffic flow and how to
 * interpret the address fields for end-to-end communication tracking.
 *
 * ToDS = "To Distribution System" (toward wired network/internet)
 * FromDS = "From Distribution System" (from wired network/internet)
 *
 * TRAFFIC DIRECTION COMBINATIONS:
 * - ToDS=0, FromDS=0: IBSS/Ad-hoc (device-to-device, no AP)
 * - ToDS=1, FromDS=0: Station → AP (IoT device uploading to internet)
 * - ToDS=0, FromDS=1: AP → Station (internet downloading to IoT device)
 * - ToDS=1, FromDS=1: WDS/mesh (AP-to-AP wireless bridging)
 *
 * IOT EXFILTRATION ANALYSIS:
 * - Heavy ToDS=1 traffic from device = potential data uploads/exfiltration
 * - Balanced ToDS/FromDS = normal bidirectional communication
 * - Unexpected ToDS patterns = suspicious device behavior
 *
 * ADDRESSING CHANGES PER DIRECTION:
 * See address interpretation table above for how addr1/addr2/addr3 meaning
 * shifts based on these direction bits.
 */
struct ieee802_11_frame {
    uint16_t frame_control;  // Frame type, subtype, flags (ToDS/FromDS/etc) - 2B
    uint16_t duration;       // NAV duration or Association ID - 2B
    uint8_t addr1[6];        // Address 1: Usually receiver address - 6B
    uint8_t addr2[6];        // Address 2: Usually transmitter address - 6B
    uint8_t addr3[6];        // Address 3: BSSID/DA/SA (depends on ToDS/FromDS) - 6B
    uint16_t seq_ctrl;       // Sequence control: fragment + sequence number - 2B
    // addr4[6] conditionally present - check ToDS=1 && FromDS=1
    // Frame body follows (LLC/SNAP → IP → TCP/UDP → payload)
} __attribute__((packed));

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
 * Prints human-readable MAC address from packet metadata.
 * @param uint8_t pointer to the beggining of MAC sequence
 */
void print_mac(const uint8_t *mac);

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
void start_capture(pcap_t *handle, threadpool_t *pool);
