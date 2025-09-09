#include "pcap.h"
#include <stdio.h>
#include <string.h>

static const char *icepick_banner = 
"██▓ ▄████▄   ▓█████  ██▓███   ██▓ ▄████▄   ██ ▄█▀\n"
"▓██▒▒██▀ ▀█   ▓█   ▀ ▓██░ ██▒▓██▒▒██▀ ▀█   ██▄█▒ \n"
"▒██▒▒▓█    ▄  ▒███   ▓██░ ██▓▒▒██▒▒▓█    ▄ ▓███▄░ \n"
"░██░▒▓▓▄ ▄██▒ ▒▓█  ▄ ▒██▄█▓▒ ▒░██░▒▓▓▄ ▄██▒▓██ █▄ \n"
"░██░▒ ▓███▀ ░ ░▒████▒▒██▒ ░  ░░██░▒ ▓███▀ ░▒██▒ █▄\n"
"░▓  ░ ░▒ ▒  ░ ░░ ▒░ ░▒▓▒░ ░  ░░▓  ░ ░▒ ▒  ░▒ ▒▒ ▓▒\n"
" ▒ ░  ░  ▒     ░ ░  ░░▒ ░      ▒ ░  ░  ▒   ░ ░▒ ▒░\n"
" ▒ ░░          ░ ░   ░░        ▒ ░░        ░ ░░ ░ \n"
" ░  ░ ░          ░  ░          ░  ░ ░      ░  ░   \n"
"    ░                             ░               \n";

static const bool GRACEFUL = true;
static const bool NOT_GRACEFUL = false;

void user_help() {
    printf("Icepick - Network Traffic Capture\n\n");
    printf("REQUIREMENTS:\n");
    printf("1. Wireless interface supporting monitor mode\n");
    printf("2. Compatible wireless drivers (mac80211-based)\n");
    printf("3. Root privileges for packet capture and mode changes\n\n");
    printf("NOTE: Expects 802.11_RADIOTAP datalink type for proper frame parsing\n");
    printf("      Monitor mode incompatibility will provide garbage data\n");
    printf("      NetworkManager may reset interface to managed mode if running\n\n");
    printf("Usage: ./icepick <interface> [-h|--help]\n");
    printf("       ./icepick wlan0\n");
    printf("       ./icepick wlan0mon  # if using airmon-ng\n");
}

int main(int argc, char *argv[]) {
    printf("%s", icepick_banner);
    char errbuf[PCAP_ERRBUF_SIZE];
    char *interface;

    threadpool_t *pool = threadpool_create(MAX_THREADS, MAX_QUEUE);
    if (!pool) {
        fprintf(stderr, "Failed to create threadpool\n");
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "Error: Interface name required\n");
        if (list_interfaces(errbuf) < 0) {
            fprintf(stderr, "Not able to find interfaces: %s\n", errbuf);
            threadpool_destroy(pool, NOT_GRACEFUL);
            return -2;
        }
        user_help();
        threadpool_destroy(pool, NOT_GRACEFUL);
        return -1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        user_help();
        threadpool_destroy(pool, NOT_GRACEFUL);
        return 0;
    }

    interface = argv[1];

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) != 0) {
        fprintf(stderr, "pcap init failed: %s\n", errbuf);
        threadpool_destroy(pool, NOT_GRACEFUL);
        return -1;
    }

    pcap_t *handle = create_handle(interface, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Handle creation failed: %s\n", errbuf);
        threadpool_destroy(pool, NOT_GRACEFUL);
        return -4;
    }

    start_capture(handle, pool);

    threadpool_destroy(pool, GRACEFUL);
    pcap_close(handle);
    return 0;
}
