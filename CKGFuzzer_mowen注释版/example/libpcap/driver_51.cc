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
    // Ensure the input size is sufficient for our operations
    if (size < 16) return 0;

    // Extract device name and buffer size from the fuzzer input
    size_t device_name_size = size / 2;
    size_t buffer_size_size = size - device_name_size;
    char* device_name = safe_strndup(data, device_name_size);
    if (!device_name) return 0;
    int buffer_size = safe_strntoi(data + device_name_size, buffer_size_size);

    // Error buffer for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a pcap handle
    pcap_t* pcap = pcap_create(device_name, errbuf);
    free(device_name);
    if (!pcap) return 0;

    // Use a unique_ptr to manage the pcap handle
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap_guard(pcap, [](pcap_t* p) { pcap_close(p); });

    // Set buffer size
    int set_buffer_result = pcap_set_buffer_size(pcap, buffer_size);
    if (set_buffer_result != 0) return 0;

    // Activate the pcap handle
    int activate_result = pcap_activate(pcap);
    if (activate_result < 0) return 0;

    // Retrieve and print the major and minor versions
    int major_version = pcap_major_version(pcap);
    int minor_version = pcap_minor_version(pcap);

    // Print the libpcap library version
    const char* lib_version = pcap_lib_version();

    // Ensure all resources are freed and no memory leaks occur
    return 0;
}
