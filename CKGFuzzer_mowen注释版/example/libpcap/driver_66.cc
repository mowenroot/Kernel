#include <pcap/pcap.h>
#include <pcap/can_socketcan.h>
#include <pcap/bluetooth.h>
#include <pcap/ipnet.h>
#include <pcap/usb.h>
#include <pcap/vlan.h>
#include <pcap/sll.h>
#include <pcap/nflog.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to a string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzzer input to an integer
int safe_strntoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Allocate and initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a pcap handle
    const char* device = safe_strndup(data, size / 4);
    if (!device) return 0;
    pcap_t* pcap = pcap_create(device, errbuf);
    free((void*)device);
    if (!pcap) return 0;

    // Set timestamp type
    int tstamp_type = safe_strntoi(data + size / 4, size / 4);
    if (pcap_set_tstamp_type(pcap, tstamp_type) < 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set datalink type
    int datalink_type = safe_strntoi(data + size / 2, size / 4);
    if (pcap_set_datalink(pcap, datalink_type) < 0) {
        pcap_close(pcap);
        return 0;
    }

    // Activate the pcap handle
    if (pcap_activate(pcap) < 0) {
        pcap_close(pcap);
        return 0;
    }

    // Capture a packet
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    int result = pcap_next_ex(pcap, &header, &packet_data);
    if (result < 0) {
        pcap_close(pcap);
        return 0;
    }

    // Retrieve statistics
    struct pcap_stat stats;
    if (pcap_stats(pcap, &stats) < 0) {
        pcap_close(pcap);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    return 0;
}
