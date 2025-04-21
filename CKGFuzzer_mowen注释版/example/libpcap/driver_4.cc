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
#include <algorithm> // Added for std::min
#include <string>    // Added for std::string

// Function to safely convert fuzz input to a string
std::string SafeStringFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return "";
    size_t len = std::min(size, static_cast<size_t>(1024)); // Limit string length to 1024 characters
    return std::string(reinterpret_cast<const char*>(data), len);
}

// Function to safely convert fuzz input to an integer
int SafeIntFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    size_t len = std::min(size, static_cast<size_t>(sizeof(int))); // Limit to size of int
    int result = 0;
    memcpy(&result, data, len);
    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize pcap_t handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        return 0; // Failed to initialize pcap handle
    }

    // pcap_get_tstamp_precision
    int tstamp_precision = pcap_get_tstamp_precision(pcap);
    if (tstamp_precision < 0) {
        pcap_close(pcap);
        return 0; // Error in getting timestamp precision
    }

    // pcap_datalink_val_to_name
    int dlt_val = SafeIntFromFuzzInput(data, size);
    const char* dlt_name = pcap_datalink_val_to_name(dlt_val);
    if (!dlt_name) {
        pcap_close(pcap);
        return 0; // Error in converting DLT value to name
    }

    // pcap_datalink_ext
    int dlt_ext = pcap_datalink_ext(pcap);
    if (dlt_ext < 0) {
        pcap_close(pcap);
        return 0; // Error in getting extended DLT
    }

    // pcap_datalink_name_to_val
    std::string fuzz_name = SafeStringFromFuzzInput(data, size);
    int dlt_val_from_name = pcap_datalink_name_to_val(fuzz_name.c_str());
    if (dlt_val_from_name == -1) {
        pcap_close(pcap);
        return 0; // Error in converting DLT name to value
    }

    // pcap_set_datalink
    int set_dlt_result = pcap_set_datalink(pcap, dlt_val_from_name);
    if (set_dlt_result != 0) {
        pcap_close(pcap);
        return 0; // Error in setting DLT
    }

    // pcap_list_datalinks
    int* dlt_list = nullptr;
    int dlt_count = pcap_list_datalinks(pcap, &dlt_list);
    if (dlt_count < 0) {
        pcap_close(pcap);
        free(dlt_list);
        return 0; // Error in listing DLTs
    }

    // Clean up
    free(dlt_list);
    pcap_close(pcap);
    return 0;
}
