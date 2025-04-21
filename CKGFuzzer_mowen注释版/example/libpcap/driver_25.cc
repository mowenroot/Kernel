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
#include <cstring>
#include <cstdio>
#include <algorithm> // Include the <algorithm> header for std::min

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a pcap_t structure
std::unique_ptr<pcap_t, void(*)(pcap_t*)> safe_pcap_alloc(pcap_t* p) {
    return std::unique_ptr<pcap_t, void(*)(pcap_t*)>(p, [](pcap_t* p) {
        if (p) pcap_close(p);
    });
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Extract device name from fuzz input
    size_t device_name_len = std::min(size_t(data[0]), size - 1); // Use std::min from <algorithm>
    char* device_name = safe_strndup(data + 1, device_name_len);
    if (!device_name) return 0;

    // Call pcap_lookupnet to get network and netmask
    bpf_u_int32 netp, maskp;
    int lookup_result = pcap_lookupnet(device_name, &netp, &maskp, errbuf);
    free(device_name);
    if (lookup_result != 0) return 0;

    // Open an offline pcap file with timestamp precision
    FILE* fp = fopen("input_file", "rb");
    if (!fp) return 0;
    auto pcap_handle = safe_pcap_alloc(pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf));
    if (!pcap_handle) {
        fclose(fp);
        return 0;
    }

    // Set packet capture direction
    pcap_direction_t direction = static_cast<pcap_direction_t>(data[device_name_len + 1] % 3); // 0: PCAP_D_IN, 1: PCAP_D_OUT, 2: PCAP_D_INOUT
    if (pcap_setdirection(pcap_handle.get(), direction) != 0) return 0;

    // Set timeout
    int timeout_ms = static_cast<int>(data[device_name_len + 2]) * 100; // Convert to milliseconds
    if (pcap_set_timeout(pcap_handle.get(), timeout_ms) != 0) return 0;

    // Set timestamp type
    int tstamp_type = static_cast<int>(data[device_name_len + 3] % 5); // Example types: 0-4
    if (pcap_set_tstamp_type(pcap_handle.get(), tstamp_type) != 0) return 0;

    // Clean up and return
    fclose(fp);
    return 0;
}
