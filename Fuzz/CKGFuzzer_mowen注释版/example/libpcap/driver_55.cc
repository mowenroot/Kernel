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

// Function to safely extract an integer from the fuzz input
int extractInt(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return value;
}

// Function to safely extract a string from the fuzz input
std::unique_ptr<char[]> extractString(const uint8_t* data, size_t& offset, size_t size, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr; // Return nullptr if not enough data
    }
    std::unique_ptr<char[]> str(new char[max_len + 1]);
    memcpy(str.get(), data + offset, max_len);
    str[max_len] = '\0'; // Null-terminate the string
    offset += max_len;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap(nullptr, [](pcap_t* p) { if (p) pcap_close(p); });

    // Extract device name (up to 256 characters)
    auto device_name = extractString(data, offset, size, 256);
    if (!device_name) {
        return 0; // Not enough data for device name
    }

    // Create pcap handle
    pcap.reset(pcap_create(device_name.get(), errbuf));
    if (!pcap) {
        return 0; // Failed to create pcap handle
    }

    // Extract and set promiscuous mode
    int promisc = extractInt(data, offset, size);
    if (pcap_set_promisc(pcap.get(), promisc) != 0) {
        return 0; // Failed to set promiscuous mode
    }

    // Extract and set timeout
    int timeout_ms = extractInt(data, offset, size);
    if (pcap_set_timeout(pcap.get(), timeout_ms) != 0) {
        return 0; // Failed to set timeout
    }

    // Extract and set buffer size
    int buffer_size = extractInt(data, offset, size);
    if (pcap_set_buffer_size(pcap.get(), buffer_size) != 0) {
        return 0; // Failed to set buffer size
    }

    // Extract and set snapshot length
    int snaplen = extractInt(data, offset, size);
    if (pcap_set_snaplen(pcap.get(), snaplen) != 0) {
        return 0; // Failed to set snapshot length
    }

    // Activate the pcap handle
    int status = pcap_activate(pcap.get());
    if (status < 0) {
        return 0; // Failed to activate pcap handle
    }

    // If we reach here, the pcap handle was successfully activated
    return 0;
}
