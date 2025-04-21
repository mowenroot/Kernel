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
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int val = atoi(str);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < 16) return 0;

    // Initialize pcap_t object
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) return 0;

    // Use RAII to ensure pcap_t is properly closed
    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_guard(pcap, pcap_close);

    // Extract data for API calls
    const uint8_t* name_data = data;
    size_t name_size = size / 2;
    const uint8_t* val_data = data + name_size;
    size_t val_size = size - name_size;

    // Convert fuzz input to a string and an integer
    char* name = safe_strndup(name_data, name_size);
    int val = safe_atoi(val_data, val_size);

    // Use RAII to ensure the string is properly freed
    std::unique_ptr<char, decltype(&free)> name_guard(name, free);

    // Call pcap_tstamp_type_name_to_val
    int tstamp_type = pcap_tstamp_type_name_to_val(name);
    if (tstamp_type == PCAP_ERROR) {
        // Handle error
        return 0;
    }

    // Call pcap_tstamp_type_val_to_name
    const char* tstamp_name = pcap_tstamp_type_val_to_name(tstamp_type);
    if (!tstamp_name) {
        // Handle error
        return 0;
    }

    // Call pcap_tstamp_type_val_to_description
    const char* tstamp_description = pcap_tstamp_type_val_to_description(tstamp_type);
    if (!tstamp_description) {
        // Handle error
        return 0;
    }

    // Call pcap_set_tstamp_type
    int set_tstamp_type_result = pcap_set_tstamp_type(pcap, tstamp_type);
    if (set_tstamp_type_result != 0) {
        // Handle error
        return 0;
    }

    // Call pcap_get_tstamp_precision
    int tstamp_precision = pcap_get_tstamp_precision(pcap);

    // Call pcap_set_tstamp_precision
    int set_tstamp_precision_result = pcap_set_tstamp_precision(pcap, tstamp_precision);
    if (set_tstamp_precision_result != 0) {
        // Handle error
        return 0;
    }

    // All operations completed successfully
    return 0;
}
