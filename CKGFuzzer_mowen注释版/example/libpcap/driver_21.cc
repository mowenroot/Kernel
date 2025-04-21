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
#include <algorithm> // Include this header for std::min and std::max

// Function to safely convert fuzzer input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t &offset, int min_val, int max_val) {
    if (offset + sizeof(int) > size) {
        return min_val; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return std::max(min_val, std::min(max_val, value));
}

// Function to safely convert fuzzer input to a boolean
bool safe_bool_from_data(const uint8_t *data, size_t size, size_t &offset) {
    if (offset + sizeof(bool) > size) {
        return false; // Default to false if not enough data
    }
    bool value = *reinterpret_cast<const bool*>(data + offset);
    offset += sizeof(bool);
    return value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 6) {
        return 0;
    }

    // Create a unique_ptr to manage the pcap_t object
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap_handle(pcap_open_dead(DLT_EN10MB, 65535), pcap_close);
    if (!pcap_handle) {
        return 0; // Failed to create pcap_t object
    }

    size_t offset = 0;

    // Set promiscuous mode
    int promisc = safe_bool_from_data(data, size, offset);
    if (pcap_set_promisc(pcap_handle.get(), promisc) != 0) {
        return 0; // Error setting promiscuous mode
    }

    // Set timeout
    int timeout_ms = safe_int_from_data(data, size, offset, 0, 10000); // 0 to 10000 ms
    if (pcap_set_timeout(pcap_handle.get(), timeout_ms) != 0) {
        return 0; // Error setting timeout
    }

    // Set buffer size
    int buffer_size = safe_int_from_data(data, size, offset, 1, 1024 * 1024); // 1 to 1MB
    if (pcap_set_buffer_size(pcap_handle.get(), buffer_size) != 0) {
        return 0; // Error setting buffer size
    }

    // Set immediate mode
    int immediate = safe_bool_from_data(data, size, offset);
    if (pcap_set_immediate_mode(pcap_handle.get(), immediate) != 0) {
        return 0; // Error setting immediate mode
    }

    // Set snapshot length
    int snaplen = safe_int_from_data(data, size, offset, 68, 65535); // 68 to 65535 bytes
    if (pcap_set_snaplen(pcap_handle.get(), snaplen) != 0) {
        return 0; // Error setting snapshot length
    }

    // Set data link type
    int dlt = safe_int_from_data(data, size, offset, 0, 255); // Assuming DLT values are within 0-255
    if (pcap_set_datalink(pcap_handle.get(), dlt) != 0) {
        return 0; // Error setting data link type
    }

    return 0;
}
