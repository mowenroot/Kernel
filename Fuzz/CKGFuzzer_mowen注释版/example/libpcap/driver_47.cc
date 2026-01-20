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

// Function to safely copy data to a buffer with bounds checking
void safe_copy(char *dest, size_t dest_size, const uint8_t *src, size_t src_size) {
    size_t copy_size = (src_size < dest_size) ? src_size : dest_size - 1;
    memcpy(dest, src, copy_size);
    dest[copy_size] = '\0';
}

// Function to safely open a file for reading
FILE* safe_fopen(const char *filename, const char *mode) {
    FILE *file = fopen(filename, mode);
    if (!file) {
        perror("Failed to open file");
    }
    return file;
}

// Function to safely close a file
void safe_fclose(FILE *file) {
    if (file) {
        fclose(file);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 4) {
        return 0;
    }

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Step 1: Call pcap_lookupdev to get a device name
    char *device = pcap_lookupdev(errbuf);
    if (!device) {
        // Handle error
        return 0;
    }

    // Step 2: Call pcap_set_protocol_linux with a protocol derived from input data
    int protocol = data[0]; // Use the first byte as the protocol
    pcap_t *pcap_handle = pcap_open_dead(DLT_EN10MB, 65535); // Dummy handle for setting protocol
    if (!pcap_handle) {
        // Handle error
        return 0;
    }
    int set_protocol_result = pcap_set_protocol_linux(pcap_handle, protocol);
    if (set_protocol_result != 0) {
        // Handle error
        pcap_close(pcap_handle);
        return 0;
    }

    // Step 3: Call pcap_fopen_offline to open a file for offline reading
    char filename[256];
    safe_copy(filename, sizeof(filename), data + 1, size - 1); // Use the rest of the data as a filename
    FILE *file = safe_fopen(filename, "rb");
    if (!file) {
        // Handle error
        pcap_close(pcap_handle);
        return 0;
    }
    pcap_t *offline_handle = pcap_fopen_offline(file, errbuf);
    if (!offline_handle) {
        // Handle error
        safe_fclose(file);
        pcap_close(pcap_handle);
        return 0;
    }

    // Step 4: Call pcap_set_tstamp_precision to set timestamp precision
    int tstamp_precision = (data[0] % 2 == 0) ? PCAP_TSTAMP_PRECISION_MICRO : PCAP_TSTAMP_PRECISION_NANO;
    int set_tstamp_result = pcap_set_tstamp_precision(offline_handle, tstamp_precision);
    if (set_tstamp_result != 0) {
        // Handle error
        pcap_close(offline_handle);
        safe_fclose(file);
        pcap_close(pcap_handle);
        return 0;
    }

    // Clean up resources
    pcap_close(offline_handle);
    safe_fclose(file);
    pcap_close(pcap_handle);

    return 0;
}
