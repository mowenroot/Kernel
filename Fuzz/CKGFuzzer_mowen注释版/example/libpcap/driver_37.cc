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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
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

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Extract device name from fuzz input
    size_t device_name_len = data[0];
    if (device_name_len >= size) return 0;
    char* device_name = safe_strndup(data + 1, device_name_len);
    if (!device_name) return 0;

    // Create a pcap handle
    pcap_t* pcap = pcap_create(device_name, errbuf);
    free(device_name);
    if (!pcap) return 0;

    // Set snapshot length
    int snaplen = safe_atoi(data + 1 + device_name_len, 4);
    if (pcap_set_snaplen(pcap, snaplen) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set data link type
    int dlt = safe_atoi(data + 1 + device_name_len + 4, 4);
    if (pcap_set_datalink(pcap, dlt) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Find all devices
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Free all devices
    pcap_freealldevs(alldevs);

    // Apply a filter (dummy filter for demonstration)
    struct bpf_program fp;
    if (pcap_setfilter(pcap, &fp) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    return 0;
}
