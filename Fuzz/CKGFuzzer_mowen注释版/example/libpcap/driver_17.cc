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

// Function to create a FILE pointer from the fuzzer input data
FILE* create_file_from_data(const uint8_t* data, size_t size) {
    // Create a temporary file and write the fuzzer input data to it
    FILE* fp = tmpfile();
    if (!fp) {
        return nullptr;
    }
    fwrite(data, 1, size, fp);
    rewind(fp); // Reset the file pointer to the beginning
    return fp;
}

// Function to free the resources allocated by pcap_list_tstamp_types
void free_tstamp_types(int* tstamp_types) {
    if (tstamp_types) {
        free(tstamp_types);
    }
}

// The main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Create a FILE pointer from the fuzzer input data
    std::unique_ptr<FILE, int(*)(FILE*)> fp(create_file_from_data(data, size), fclose);
    if (!fp) {
        return 0;
    }

    // Allocate a buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Open the file for offline reading with a specified timestamp precision
    u_int precision = data[0]; // Use the first byte as the precision
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> pcap(pcap_fopen_offline_with_tstamp_precision(fp.get(), precision, errbuf), pcap_close);
    if (!pcap) {
        return 0;
    }

    // Set the protocol for the pcap handle
    int protocol = *reinterpret_cast<const int*>(data + 1); // Use the next 4 bytes as the protocol
    int set_protocol_result = pcap_set_protocol_linux(pcap.get(), protocol);
    if (set_protocol_result != 0) {
        return 0;
    }

    // Get the timestamp precision from the pcap handle
    int tstamp_precision = pcap_get_tstamp_precision(pcap.get());

    // List the supported timestamp types
    int* tstamp_types = nullptr;
    int tstamp_type_count = pcap_list_tstamp_types(pcap.get(), &tstamp_types);
    if (tstamp_type_count < 0) {
        free_tstamp_types(tstamp_types);
        return 0;
    }

    // Set the timestamp type if supported
    int tstamp_type = data[5]; // Use the 6th byte as the timestamp type
    int set_tstamp_type_result = pcap_set_tstamp_type(pcap.get(), tstamp_type);
    if (set_tstamp_type_result != 0 && set_tstamp_type_result != PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {
        free_tstamp_types(tstamp_types);
        return 0;
    }

    // Free the allocated timestamp types list
    free_tstamp_types(tstamp_types);

    return 0;
}
