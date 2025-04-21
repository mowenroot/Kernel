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

// Function to create a temporary file for fuzzing
FILE* create_temp_file(const uint8_t* data, size_t size) {
    FILE* temp_file = tmpfile();
    if (!temp_file) {
        perror("Failed to create temporary file");
        return nullptr;
    }
    if (fwrite(data, 1, size, temp_file) != size) {
        perror("Failed to write to temporary file");
        fclose(temp_file);
        return nullptr;
    }
    rewind(temp_file);
    return temp_file;
}

// Function to safely close a file
void safe_fclose(FILE* file) {
    if (file) {
        fclose(file);
    }
}

// Function to safely free a pcap_t handle
void safe_pcap_close(pcap_t* pcap) {
    if (pcap) {
        pcap_close(pcap);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a temporary file with the fuzzer input
    std::unique_ptr<FILE, decltype(&safe_fclose)> temp_file(create_temp_file(data, size), safe_fclose);
    if (!temp_file) {
        return 0;
    }

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for offline reading
    std::unique_ptr<pcap_t, decltype(&safe_pcap_close)> pcap(
        pcap_fopen_offline_with_tstamp_precision(temp_file.get(), PCAP_TSTAMP_PRECISION_MICRO, errbuf),
        safe_pcap_close
    );
    if (!pcap) {
        pcap_perror(nullptr, "pcap_fopen_offline_with_tstamp_precision failed");
        return 0;
    }

    // Set timestamp precision
    if (pcap_set_tstamp_precision(pcap.get(), PCAP_TSTAMP_PRECISION_MICRO) != 0) {
        pcap_perror(pcap.get(), "pcap_set_tstamp_precision failed");
        return 0;
    }

    // Set timeout
    if (pcap_set_timeout(pcap.get(), 1000) != 0) {
        pcap_perror(pcap.get(), "pcap_set_timeout failed");
        return 0;
    }

    // Set snaplen
    if (pcap_set_snaplen(pcap.get(), 65535) != 0) {
        pcap_perror(pcap.get(), "pcap_set_snaplen failed");
        return 0;
    }

    // Successfully configured pcap handle
    return 0;
}
