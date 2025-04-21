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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate and initialize an array from fuzz input
int* safe_int_array(const uint8_t* data, size_t size) {
    if (size == 0 || size % sizeof(int) != 0) return nullptr;
    int* arr = (int*)malloc(size);
    if (!arr) return nullptr;
    memcpy(arr, data, size);
    return arr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // Step 1: Call pcap_findalldevs
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        // Handle error
        return 0;
    }

    // Step 2: Call pcap_freealldevs
    if (alldevs) {
        pcap_freealldevs(alldevs);
    }

    // Step 3: Allocate and free a timestamp type list
    int* tstamp_type_list = safe_int_array(data, size);
    if (tstamp_type_list) {
        pcap_free_tstamp_types(tstamp_type_list);
    }

    // Step 4: Allocate and free a data link type list
    int* dlt_list = safe_int_array(data, size);
    if (dlt_list) {
        pcap_free_datalinks(dlt_list);
    }

    // Step 5: Allocate and free a BPF program
    struct bpf_program program;
    program.bf_len = 0;
    program.bf_insns = nullptr;
    pcap_freecode(&program);

    // Step 6: Open and close a pcap dump file
    pcap_dumper_t* dumper = pcap_dump_open(nullptr, "output_file");
    if (dumper) {
        pcap_dump_close(dumper);
    }

    // Ensure all allocated memory is freed
    free(tstamp_type_list);
    free(dlt_list);

    return 0;
}
