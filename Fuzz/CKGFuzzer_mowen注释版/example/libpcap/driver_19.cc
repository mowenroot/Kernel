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
#include <cstdio>

// Function to create a FILE* from the fuzzer input data
FILE* create_file_from_data(const uint8_t* data, size_t size) {
    // Create a temporary file
    FILE* fp = tmpfile();
    if (!fp) {
        return nullptr;
    }

    // Write the fuzzer input data to the temporary file
    size_t written = fwrite(data, 1, size, fp);
    if (written != size) {
        fclose(fp);
        return nullptr;
    }

    // Rewind the file pointer to the beginning
    rewind(fp);
    return fp;
}

// Function to safely close the FILE*
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is at least 4 bytes for the magic number
    if (size < 4) {
        return 0;
    }

    // Create a temporary file from the fuzzer input data
    std::unique_ptr<FILE, decltype(&safe_fclose)> fp(create_file_from_data(data, size), safe_fclose);
    if (!fp) {
        return 0;
    }

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file with timestamp precision
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(fp.get(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        return 0;
    }

    // Use RAII to manage the pcap_t* resource
    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_guard(pcap, pcap_close);

    // Set timestamp precision
    int tstamp_precision = data[0] % 2 == 0 ? PCAP_TSTAMP_PRECISION_MICRO : PCAP_TSTAMP_PRECISION_NANO;
    if (pcap_set_tstamp_precision(pcap, tstamp_precision) != 0) {
        return 0;
    }

    // Set timeout
    int timeout_ms = (data[1] << 8) | data[2];
    if (pcap_set_timeout(pcap, timeout_ms) != 0) {
        return 0;
    }

    // Set snaplen
    int snaplen = (data[3] << 8) | data[4];
    if (pcap_set_snaplen(pcap, snaplen) != 0) {
        return 0;
    }

    // Set datalink type
    int dlt = data[5] % 256; // Assuming DLT values are within 0-255
    if (pcap_set_datalink(pcap, dlt) != 0) {
        return 0;
    }

    // If we reach here, all API calls were successful
    return 0;
}
