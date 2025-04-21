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
#include <cstring>
#include <cstdio>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a FILE pointer from fuzz input
FILE* safe_fopen(const char* filename, const char* mode) {
    FILE* fp = fopen(filename, mode);
    if (!fp) {
        perror("fopen");
    }
    return fp;
}

// Function to safely close a FILE pointer
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 4) return 0;

    // Initialize variables
    pcap_t* pcap = nullptr;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;

    // Create a temporary file for pcap_fopen_offline_with_tstamp_precision
    FILE* fp = tmpfile();
    if (!fp) {
        return 0;
    }

    // Write some data to the temporary file
    fwrite(data, 1, size, fp);
    rewind(fp);

    // Open the pcap file with specified timestamp precision
    pcap = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        safe_fclose(fp);
        return 0;
    }

    // Set the protocol for Linux
    int protocol = data[0];
    result = pcap_set_protocol_linux(pcap, protocol);
    if (result != 0) {
        pcap_close(pcap);
        safe_fclose(fp);
        return 0;
    }

    // Set the timestamp precision
    int tstamp_precision = data[1];
    result = pcap_set_tstamp_precision(pcap, tstamp_precision);
    if (result != 0) {
        pcap_close(pcap);
        safe_fclose(fp);
        return 0;
    }

    // Get the timestamp precision
    int retrieved_precision = pcap_get_tstamp_precision(pcap);
    if (retrieved_precision != tstamp_precision) {
        pcap_close(pcap);
        safe_fclose(fp);
        return 0;
    }

    // Compile the filter expression
    char* filter_exp = safe_strndup(data + 2, size - 2);
    if (!filter_exp) {
        pcap_close(pcap);
        safe_fclose(fp);
        return 0;
    }

    result = pcap_compile(pcap, &bpf, filter_exp, 1, PCAP_NETMASK_UNKNOWN);
    free(filter_exp);
    if (result != 0) {
        pcap_close(pcap);
        safe_fclose(fp);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    safe_fclose(fp);

    return 0;
}
