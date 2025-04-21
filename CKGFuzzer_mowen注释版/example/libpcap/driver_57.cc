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
int extractInt(const uint8_t*& data, size_t& size, size_t& bytesRead) {
    if (size < sizeof(int)) {
        return 0; // Return a default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data);
    data += sizeof(int);
    size -= sizeof(int);
    bytesRead += sizeof(int);
    return value;
}

// Function to safely extract a boolean from the fuzz input
bool extractBool(const uint8_t*& data, size_t& size, size_t& bytesRead) {
    if (size < sizeof(bool)) {
        return false; // Return a default value if not enough data
    }
    bool value = *reinterpret_cast<const bool*>(data);
    data += sizeof(bool);
    size -= sizeof(bool);
    bytesRead += sizeof(bool);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < (6 * sizeof(int)) + sizeof(bool)) {
        return 0; // Not enough data to proceed
    }

    // Create a unique_ptr to manage the pcap_t object
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap(pcap_open_dead(DLT_EN10MB, 65535), [](pcap_t* p) { pcap_close(p); });
    if (!pcap) {
        return 0; // Failed to create pcap_t object
    }

    size_t bytesRead = 0;

    // Extract and set promiscuous mode
    int promisc = extractInt(data, size, bytesRead);
    if (pcap_set_promisc(pcap.get(), promisc) != 0) {
        return 0; // Error setting promiscuous mode
    }

    // Extract and set timeout
    int timeout_ms = extractInt(data, size, bytesRead);
    if (pcap_set_timeout(pcap.get(), timeout_ms) != 0) {
        return 0; // Error setting timeout
    }

    // Extract and set buffer size
    int buffer_size = extractInt(data, size, bytesRead);
    if (pcap_set_buffer_size(pcap.get(), buffer_size) != 0) {
        return 0; // Error setting buffer size
    }

    // Extract and set immediate mode
    bool immediate = extractBool(data, size, bytesRead);
    if (pcap_set_immediate_mode(pcap.get(), immediate) != 0) {
        return 0; // Error setting immediate mode
    }

    // Extract and set snaplen
    int snaplen = extractInt(data, size, bytesRead);
    if (pcap_set_snaplen(pcap.get(), snaplen) != 0) {
        return 0; // Error setting snaplen
    }

    // Extract and set datalink
    int dlt = extractInt(data, size, bytesRead);
    if (pcap_set_datalink(pcap.get(), dlt) != 0) {
        return 0; // Error setting datalink
    }

    // All operations completed successfully
    return 0;
}
