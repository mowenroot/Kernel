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
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely copy a string from fuzz input with a limit
char* safe_strndup_limited(const uint8_t* data, size_t size, size_t limit) {
    if (size == 0 || limit == 0) return nullptr;
    size_t copy_size = (size < limit) ? size : limit;
    char* str = (char*)malloc(copy_size + 1);
    if (!str) return nullptr;
    memcpy(str, data, copy_size);
    str[copy_size] = '\0';
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Extract device name from fuzz input
    size_t device_name_len = data[0];
    if (device_name_len >= size) return 0;
    char* device_name = safe_strndup(data + 1, device_name_len);
    if (!device_name) return 0;

    // Extract filter expression from fuzz input
    size_t filter_expr_len = data[device_name_len + 1];
    if (filter_expr_len >= size - device_name_len - 2) return 0;
    char* filter_expr = safe_strndup(data + device_name_len + 2, filter_expr_len);
    if (!filter_expr) {
        free(device_name);
        return 0;
    }

    // Initialize network and netmask variables
    bpf_u_int32 netp = 0, maskp = 0;

    // Call pcap_lookupnet to get network and netmask
    int lookup_result = pcap_lookupnet(device_name, &netp, &maskp, errbuf);
    if (lookup_result != 0) {
        free(device_name);
        free(filter_expr);
        return 0;
    }

    // Open an offline pcap file for reading
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        free(device_name);
        free(filter_expr);
        return 0;
    }

    // Open the pcap file with timestamp precision
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        fclose(fp);
        free(device_name);
        free(filter_expr);
        return 0;
    }

    // Compile the filter expression
    struct bpf_program fp_prog;
    int compile_result = pcap_compile(pcap, &fp_prog, filter_expr, 1, maskp);
    if (compile_result != 0) {
        pcap_close(pcap);
        fclose(fp);
        free(device_name);
        free(filter_expr);
        return 0;
    }

    // Set the filter
    int setfilter_result = pcap_setfilter(pcap, &fp_prog);
    if (setfilter_result != 0) {
        pcap_freecode(&fp_prog);
        pcap_close(pcap);
        fclose(fp);
        free(device_name);
        free(filter_expr);
        return 0;
    }

    // Free the compiled filter program
    pcap_freecode(&fp_prog);

    // Close the pcap handle and file
    pcap_close(pcap);
    fclose(fp);

    // Free allocated memory
    free(device_name);
    free(filter_expr);

    return 0;
}
