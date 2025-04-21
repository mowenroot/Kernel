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
#include <cstdio>

// Function to safely convert fuzz input to an integer
int safe_int_from_data(const uint8_t* data, size_t size, size_t offset, int& value) {
    if (offset + sizeof(int) > size) {
        return -1; // Not enough data
    }
    memcpy(&value, data + offset, sizeof(int));
    return 0;
}

// Function to safely convert fuzz input to a string
int safe_string_from_data(const uint8_t* data, size_t size, size_t offset, char* str, size_t max_len) {
    if (offset + max_len > size) {
        return -1; // Not enough data
    }
    memcpy(str, data + offset, max_len);
    str[max_len - 1] = '\0'; // Ensure null-termination
    return 0;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    int immediate_mode, protocol, rfmon, snaplen;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        return 0; // Unable to open file
    }

    // Safely extract values from fuzz input
    if (safe_int_from_data(data, size, 0, immediate_mode) != 0 ||
        safe_int_from_data(data, size, sizeof(int), protocol) != 0 ||
        safe_int_from_data(data, size, 2 * sizeof(int), rfmon) != 0 ||
        safe_int_from_data(data, size, 3 * sizeof(int), snaplen) != 0) {
        fclose(fp);
        return 0; // Not enough data
    }

    // Open pcap file with timestamp precision
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap(pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf), [](pcap_t* p) { pcap_close(p); });
    if (!pcap) {
        fclose(fp);
        return 0; // Failed to open pcap file
    }

    // Set immediate mode
    if (pcap_set_immediate_mode(pcap.get(), immediate_mode) != 0) {
        return 0; // Error setting immediate mode
    }

    // Set protocol
    if (pcap_set_protocol_linux(pcap.get(), protocol) != 0) {
        return 0; // Error setting protocol
    }

    // Set monitor mode
    if (pcap_set_rfmon(pcap.get(), rfmon) != 0) {
        return 0; // Error setting monitor mode
    }

    // Set snapshot length
    if (pcap_set_snaplen(pcap.get(), snaplen) != 0) {
        return 0; // Error setting snapshot length
    }

    // No need to close fp explicitly, pcap_close will handle it
    return 0;
}
