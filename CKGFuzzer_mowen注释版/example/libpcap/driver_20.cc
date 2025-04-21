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
#include <algorithm> // Include for std::min

// Function to safely convert fuzzer input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t offset, int max_value) {
    if (offset + sizeof(int) > size) {
        return 0; // Default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    return std::min(value, max_value); // Use std::min instead of std::fmin
}

// Function to safely convert fuzzer input to a string
const char* safe_string_from_data(const uint8_t *data, size_t size, size_t offset, size_t max_length) {
    if (offset + max_length > size) {
        return nullptr; // Return nullptr if not enough data
    }
    return reinterpret_cast<const char*>(data + offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 4) {
        return 0;
    }

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a unique_ptr to manage the pcap_t resource
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap_handle(nullptr, [](pcap_t* p) {
        if (p) pcap_close(p);
    });

    // Open a pcap file for offline reading
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        return 0; // Unable to open file
    }

    pcap_handle.reset(pcap_fopen_offline(fp, errbuf));
    if (!pcap_handle) {
        fclose(fp);
        return 0; // Failed to open pcap file
    }

    // Set immediate mode
    int immediate_mode = safe_int_from_data(data, size, 0, 1);
    if (pcap_set_immediate_mode(pcap_handle.get(), immediate_mode) != 0) {
        return 0; // Failed to set immediate mode
    }

    // Set timestamp precision
    int tstamp_precision = safe_int_from_data(data, size, sizeof(int), PCAP_TSTAMP_PRECISION_NANO);
    if (pcap_set_tstamp_precision(pcap_handle.get(), tstamp_precision) != 0) {
        return 0; // Failed to set timestamp precision
    }

    // Set timeout
    int timeout_ms = safe_int_from_data(data, size, sizeof(int) * 2, 1000);
    if (pcap_set_timeout(pcap_handle.get(), timeout_ms) != 0) {
        return 0; // Failed to set timeout
    }

    // Set datalink type
    int datalink_type = safe_int_from_data(data, size, sizeof(int) * 3, DLT_EN10MB);
    if (pcap_set_datalink(pcap_handle.get(), datalink_type) != 0) {
        return 0; // Failed to set datalink type
    }

    // Close the file after use
    fclose(fp);

    return 0;
}
