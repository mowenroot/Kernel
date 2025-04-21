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

// Function to safely allocate memory for a string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a buffer
void* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    void* ptr = malloc(size);
    if (!ptr) return nullptr;
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    pcap_t* pcap = nullptr;
    struct bpf_program filter;
    const char* device = "any";
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;

    // Open a pcap handle
    pcap = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        return 0;
    }

    // Set a filter based on the input data
    char* filter_exp = safe_strndup(data, size);
    if (!filter_exp) {
        pcap_close(pcap);
        return 0;
    }

    result = pcap_compile(pcap, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    if (result == 0) {
        result = pcap_setfilter(pcap, &filter);
        pcap_freecode(&filter);
    }

    if (result != 0) {
        safe_free(filter_exp);
        pcap_close(pcap);
        return 0;
    }

    // Inject a packet based on the input data
    void* packet = safe_malloc(size);
    if (!packet) {
        safe_free(filter_exp);
        pcap_close(pcap);
        return 0;
    }
    memcpy(packet, data, size);

    result = pcap_inject(pcap, packet, size);
    safe_free(packet);
    if (result == PCAP_ERROR) {
        safe_free(filter_exp);
        pcap_close(pcap);
        return 0;
    }

    // Capture the next packet
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    result = pcap_next_ex(pcap, &header, &pkt_data);
    if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK) {
        safe_free(filter_exp);
        pcap_close(pcap);
        return 0;
    }

    // Break the loop if needed
    pcap_breakloop(pcap);

    // Clean up
    safe_free(filter_exp);
    pcap_close(pcap);

    return 0;
}
