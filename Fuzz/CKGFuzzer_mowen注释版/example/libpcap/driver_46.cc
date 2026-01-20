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

// Function to safely convert fuzz input to an integer
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
    // Ensure we have enough data for basic operations
    if (size < 4) return 0;

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a pcap handle
    const char* device_name = "input_file"; // Use a dummy device name
    pcap_t* pcap = pcap_create(device_name, errbuf);
    if (!pcap) {
        return 0; // Failed to create pcap handle
    }

    // Extract data link type from fuzz input
    int dlt = safe_strntoi(data, size / 2);
    if (dlt < 0) dlt = 0; // Ensure non-negative value

    // Set the data link type
    if (pcap_set_datalink(pcap, dlt) != 0) {
        pcap_close(pcap);
        return 0; // Failed to set data link type
    }

    // List supported data links
    int* dlt_list = nullptr;
    int dlt_count = pcap_list_datalinks(pcap, &dlt_list);
    if (dlt_count < 0) {
        pcap_close(pcap);
        return 0; // Failed to list data links
    }

    // Free the list of data links
    pcap_free_datalinks(dlt_list);

    // Convert data link type to name
    const char* dlt_name = pcap_datalink_val_to_name(dlt);
    if (!dlt_name) {
        pcap_close(pcap);
        return 0; // Failed to convert data link type to name
    }

    // Convert data link name back to value
    int dlt_from_name = pcap_datalink_name_to_val(dlt_name);
    if (dlt_from_name != dlt) {
        pcap_close(pcap);
        return 0; // Data link type mismatch
    }

    // Close the pcap handle
    pcap_close(pcap);

    return 0;
}
