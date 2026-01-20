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
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 4) return 0;

    // Initialize pcap_t and pcap_dumper_t pointers
    pcap_t* pcap = nullptr;
    pcap_dumper_t* dumper = nullptr;
    FILE* file = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Extract file name from fuzz input
    size_t filename_size = size / 2;
    char* filename = safe_strndup(data, filename_size);
    if (!filename) return 0;

    // Extract other parameters from fuzz input
    int dlt = safe_atoi(data + filename_size, size - filename_size);
    int tstamp_type = safe_atoi(data + filename_size, size - filename_size);
    int promisc = safe_atoi(data + filename_size, size - filename_size);

    // Open the file for offline reading
    file = fopen(filename, "rb");
    if (!file) {
        free(filename);
        return 0;
    }

    // Open the pcap file with timestamp precision
    pcap = pcap_fopen_offline_with_tstamp_precision(file, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        fclose(file);
        free(filename);
        return 0;
    }

    // Set the data link type
    if (pcap_set_datalink(pcap, dlt) == -1) {
        pcap_close(pcap);
        fclose(file);
        free(filename);
        return 0;
    }

    // Set the timestamp type
    if (pcap_set_tstamp_type(pcap, tstamp_type) == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {
        pcap_close(pcap);
        fclose(file);
        free(filename);
        return 0;
    }

    // Set promiscuous mode
    if (pcap_set_promisc(pcap, promisc) == PCAP_ERROR_ACTIVATED) {
        pcap_close(pcap);
        fclose(file);
        free(filename);
        return 0;
    }

    // Open the file for dumping
    dumper = pcap_dump_open(pcap, "output_file");
    if (!dumper) {
        pcap_close(pcap);
        fclose(file);
        free(filename);
        return 0;
    }

    // Clean up resources
    pcap_dump_close(dumper);
    pcap_close(pcap);
    fclose(file);
    free(filename);

    return 0;
}
