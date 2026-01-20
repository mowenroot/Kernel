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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a FILE* from fuzz input
FILE* safe_fopen(const char* filename, const char* mode) {
    FILE* fp = fopen(filename, mode);
    if (!fp) {
        perror("fopen");
    }
    return fp;
}

// Function to safely close a FILE*
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 20) return 0;

    // Extract parameters from fuzz input
    int snaplen = data[0];
    int linktype = data[1];
    int optimize = data[2];
    bpf_u_int32 mask = data[3];
    int protocol = data[4];
    int tstamp_precision = data[5];
    int dlt = data[6];
    size_t filter_size = data[7];
    size_t filename_size = data[8];

    // Ensure we have enough data for the filter and filename
    if (size < 9 + filter_size + filename_size) return 0;

    // Extract filter and filename from fuzz input
    const char* filter = (const char*)&data[9];
    const char* filename = (const char*)&data[9 + filter_size];

    // Allocate memory for the filter string
    char* filter_str = safe_strndup((const uint8_t*)filter, filter_size);
    if (!filter_str) return 0;

    // Allocate memory for the filename string
    char* filename_str = safe_strndup((const uint8_t*)filename, filename_size);
    if (!filename_str) {
        free(filter_str);
        return 0;
    }

    // Compile the filter
    struct bpf_program fp;
    int compile_result = pcap_compile_nopcap(snaplen, linktype, &fp, filter_str, optimize, mask);
    if (compile_result == -1) {
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Open the file for offline reading
    FILE* fp_file = safe_fopen(filename_str, "rb");
    if (!fp_file) {
        pcap_freecode(&fp);
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Open the pcap handle with timestamp precision
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(fp_file, tstamp_precision, errbuf);
    if (!pcap) {
        pcap_freecode(&fp);
        safe_fclose(fp_file);
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Set the protocol
    int set_protocol_result = pcap_set_protocol_linux(pcap, protocol);
    if (set_protocol_result == PCAP_ERROR_ACTIVATED) {
        pcap_close(pcap);
        pcap_freecode(&fp);
        safe_fclose(fp_file);
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Set the timestamp precision
    int set_tstamp_result = pcap_set_tstamp_precision(pcap, tstamp_precision);
    if (set_tstamp_result == PCAP_ERROR_TSTAMP_PRECISION_NOTSUP) {
        pcap_close(pcap);
        pcap_freecode(&fp);
        safe_fclose(fp_file);
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Set the datalink type
    int set_datalink_result = pcap_set_datalink(pcap, dlt);
    if (set_datalink_result == -1) {
        pcap_close(pcap);
        pcap_freecode(&fp);
        safe_fclose(fp_file);
        free(filter_str);
        free(filename_str);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    pcap_freecode(&fp);
    safe_fclose(fp_file);
    free(filter_str);
    free(filename_str);

    return 0;
}
