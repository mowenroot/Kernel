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
#include <algorithm> // Include for std::min and std::max

// Function to safely convert fuzzer input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t &offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return std::max(min, std::min(value, max)); // Clamp value within range
}

// Function to safely convert fuzzer input to a string
const char* safe_string_from_data(const uint8_t *data, size_t size, size_t &offset, size_t max_len) {
    size_t len = std::min(size - offset, max_len);
    char *str = new char[len + 1];
    memcpy(str, data + offset, len);
    str[len] = '\0';
    offset += len;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 4) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::unique_ptr<char[]> device_name;
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap_handle(nullptr, [](pcap_t* p) { if (p) pcap_close(p); });

    // Extract and set parameters from fuzzer input
    int promisc = safe_int_from_data(data, size, offset, 0, 1);
    int timeout_ms = safe_int_from_data(data, size, offset, 0, 1000);
    int buffer_size = safe_int_from_data(data, size, offset, 1, 1024 * 1024);
    int snaplen = safe_int_from_data(data, size, offset, 1, 65535);

    // Safely extract device name
    device_name.reset(const_cast<char*>(safe_string_from_data(data, size, offset, 256)));

    // Create pcap handle
    pcap_handle.reset(pcap_create(device_name.get(), errbuf));
    if (!pcap_handle) {
        return 0; // Failed to create pcap handle
    }

    // Set promiscuous mode
    if (pcap_set_promisc(pcap_handle.get(), promisc) != 0) {
        return 0; // Failed to set promiscuous mode
    }

    // Set timeout
    if (pcap_set_timeout(pcap_handle.get(), timeout_ms) != 0) {
        return 0; // Failed to set timeout
    }

    // Set buffer size
    if (pcap_set_buffer_size(pcap_handle.get(), buffer_size) != 0) {
        return 0; // Failed to set buffer size
    }

    // Set snapshot length
    if (pcap_set_snaplen(pcap_handle.get(), snaplen) != 0) {
        return 0; // Failed to set snapshot length
    }

    // Activate pcap handle
    int status = pcap_activate(pcap_handle.get());
    if (status < 0) {
        return 0; // Failed to activate pcap handle
    }

    return 0;
}
