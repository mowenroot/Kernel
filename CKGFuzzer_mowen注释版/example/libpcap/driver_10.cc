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
#include <string> // Added to resolve std::string errors
#include <algorithm> // Added to use std::min
#include <cstdio> // Added for FILE* operations

// Function to safely convert fuzz input to a string
std::string SafeStringFromFuzzInput(const uint8_t* data, size_t size, size_t max_size = 256) {
    size_t len = std::min(size, max_size); // Use std::min from <algorithm>
    return std::string(reinterpret_cast<const char*>(data), len);
}

// Function to safely convert fuzz input to an integer
int SafeIntFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    return static_cast<int>(data[0]);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Create a unique_ptr to manage the pcap_t object
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap_handle(nullptr, [](pcap_t* p) {
        if (p) pcap_close(p);
    });

    // Create a unique_ptr to manage the pcap_dumper_t object
    std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)> pcap_dumper(nullptr, [](pcap_dumper_t* d) {
        if (d) pcap_dump_close(d);
    });

    // Create a unique_ptr to manage the FILE object
    std::unique_ptr<FILE, decltype(&fclose)> file_handle(nullptr, fclose);

    // Extract file name from fuzz input
    std::string file_name = SafeStringFromFuzzInput(data, size);
    if (file_name.empty()) return 0;

    // Extract timestamp precision from fuzz input
    int tstamp_precision = SafeIntFromFuzzInput(data + file_name.size(), size - file_name.size());

    // Extract protocol from fuzz input
    int protocol = SafeIntFromFuzzInput(data + file_name.size() + 1, size - file_name.size() - 1);

    // Extract datalink type from fuzz input
    int datalink = SafeIntFromFuzzInput(data + file_name.size() + 2, size - file_name.size() - 2);

    // Open the file for offline reading with specified timestamp precision
    char errbuf[PCAP_ERRBUF_SIZE];
    file_handle.reset(fopen(file_name.c_str(), "rb"));
    if (!file_handle) return 0;

    pcap_handle.reset(pcap_fopen_offline_with_tstamp_precision(file_handle.get(), tstamp_precision, errbuf));
    if (!pcap_handle) return 0;

    // Set the timestamp precision
    if (pcap_set_tstamp_precision(pcap_handle.get(), tstamp_precision) != 0) return 0;

    // Set the protocol
    if (pcap_set_protocol_linux(pcap_handle.get(), protocol) != 0) return 0;

    // Set the datalink type
    if (pcap_set_datalink(pcap_handle.get(), datalink) != 0) return 0;

    // Open the file for appending
    pcap_dumper.reset(pcap_dump_open_append(pcap_handle.get(), file_name.c_str()));
    if (!pcap_dumper) return 0;

    // Successfully executed all API calls
    return 0;
}
