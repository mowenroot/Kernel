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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get an integer from fuzz input
int safe_get_int(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(int) > size) return 0;
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(int) * 2) return 0;

    // Initialize variables
    size_t offset = 0;
    char* device_name = nullptr;
    pcap_t* pcap_handle = nullptr;
    int major_version = 0;
    int minor_version = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Safely extract device name from fuzz input
    size_t device_name_len = safe_get_int(data, size, offset);
    if (offset + device_name_len > size) return 0;
    device_name = safe_strndup(data + offset, device_name_len);
    offset += device_name_len;

    // Create pcap handle
    pcap_handle = pcap_create(device_name, errbuf);
    if (!pcap_handle) {
        free(device_name);
        return 0;
    }

    // Activate pcap handle
    int activate_status = pcap_activate(pcap_handle);
    if (activate_status < 0) {
        pcap_close(pcap_handle);
        free(device_name);
        return 0;
    }

    // Retrieve major and minor versions
    major_version = pcap_major_version(pcap_handle);
    minor_version = pcap_minor_version(pcap_handle);

    // Clean up
    pcap_close(pcap_handle);
    free(device_name);

    return 0;
}
