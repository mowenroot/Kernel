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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
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

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Extract parameters from fuzz input
    size_t offset = 0;
    int snaplen = safe_atoi(data + offset, 4);
    offset += 4;
    int linktype = safe_atoi(data + offset, 4);
    offset += 4;
    int optimize = safe_atoi(data + offset, 4);
    offset += 4;
    int buffer_size = safe_atoi(data + offset, 4);
    offset += 4;
    int tstamp_type = safe_atoi(data + offset, 4);
    offset += 4;
    int promisc = safe_atoi(data + offset, 4);
    offset += 4;

    // Ensure we have enough data for the filter expression
    if (size - offset < 4) return 0;
    size_t filter_len = safe_atoi(data + offset, 4);
    offset += 4;

    if (size - offset < filter_len) return 0;
    char* filter_exp = safe_strndup(data + offset, filter_len);
    offset += filter_len;

    // Compile the filter expression
    struct bpf_program fp;
    int compile_result = pcap_compile_nopcap(snaplen, linktype, &fp, filter_exp, optimize, 0);
    if (compile_result != 0) {
        free(filter_exp);
        pcap_freecode(&fp);
        return 0;
    }

    // Open an offline pcap file
    FILE* fp_file = fopen("input_file", "rb");
    if (!fp_file) {
        free(filter_exp);
        pcap_freecode(&fp);
        return 0;
    }

    pcap_t* pcap = pcap_fopen_offline(fp_file, errbuf);
    if (!pcap) {
        free(filter_exp);
        pcap_freecode(&fp);
        fclose(fp_file);
        return 0;
    }

    // Set buffer size
    int set_buffer_result = pcap_set_buffer_size(pcap, buffer_size);
    if (set_buffer_result != 0) {
        free(filter_exp);
        pcap_freecode(&fp);
        pcap_close(pcap);
        fclose(fp_file);
        return 0;
    }

    // Set timestamp type
    int set_tstamp_result = pcap_set_tstamp_type(pcap, tstamp_type);
    if (set_tstamp_result != 0) {
        free(filter_exp);
        pcap_freecode(&fp);
        pcap_close(pcap);
        fclose(fp_file);
        return 0;
    }

    // Set promiscuous mode
    int set_promisc_result = pcap_set_promisc(pcap, promisc);
    if (set_promisc_result != 0) {
        free(filter_exp);
        pcap_freecode(&fp);
        pcap_close(pcap);
        fclose(fp_file);
        return 0;
    }

    // Clean up
    free(filter_exp);
    pcap_freecode(&fp);
    pcap_close(pcap);
    fclose(fp_file);

    return 0;
}
