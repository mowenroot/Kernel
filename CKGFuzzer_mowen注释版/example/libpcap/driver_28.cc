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
#include <string> // Added to include std::string
#include <algorithm> // Added to include std::min

// Function to safely convert a portion of the fuzz input to an integer
int safe_convert_to_int(const uint8_t* data, size_t size, size_t offset, size_t length) {
    if (offset + length > size) {
        return 0; // Return a default value if out of bounds
    }
    int value = 0;
    for (size_t i = 0; i < length; ++i) {
        value = (value << 8) | data[offset + i];
    }
    return value;
}

// Function to safely convert a portion of the fuzz input to a string
std::string safe_convert_to_string(const uint8_t* data, size_t size, size_t offset, size_t max_length) {
    if (offset >= size) {
        return ""; // Return an empty string if out of bounds
    }
    size_t length = std::min(max_length, size - offset);
    return std::string(reinterpret_cast<const char*>(data + offset), length);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 16) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    char errbuf[PCAP_ERRBUF_SIZE];
    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_handle(nullptr, pcap_close);

    // Extract parameters from the fuzz input
    int buffer_size = safe_convert_to_int(data, size, 0, 4);
    int datalink_type = safe_convert_to_int(data, size, 4, 4);
    int tstamp_type = safe_convert_to_int(data, size, 8, 4);
    u_int tstamp_precision = static_cast<u_int>(safe_convert_to_int(data, size, 12, 4));

    // Open an offline pcap file with the specified timestamp precision
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        return 0; // Failed to open file
    }
    pcap_handle.reset(pcap_fopen_offline_with_tstamp_precision(fp, tstamp_precision, errbuf));
    if (!pcap_handle) {
        fclose(fp);
        return 0; // Failed to open pcap handle
    }

    // Set buffer size
    if (pcap_set_buffer_size(pcap_handle.get(), buffer_size) != 0) {
        return 0; // Failed to set buffer size
    }

    // Set datalink type
    if (pcap_set_datalink(pcap_handle.get(), datalink_type) != 0) {
        return 0; // Failed to set datalink type
    }

    // Set timestamp type
    if (pcap_set_tstamp_type(pcap_handle.get(), tstamp_type) != 0) {
        return 0; // Failed to set timestamp type
    }

    // Clean up
    pcap_handle.reset(); // This will call pcap_close
    fclose(fp);

    return 0;
}
