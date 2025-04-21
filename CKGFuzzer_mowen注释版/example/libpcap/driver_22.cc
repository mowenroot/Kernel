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

// Function to safely convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size, size_t max_len) {
    if (size == 0 || size > max_len) {
        return nullptr;
    }
    char* str = (char*)malloc(size + 1);
    if (!str) {
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int fuzzInputToInt(const uint8_t* data, size_t size) {
    if (size == 0 || size > sizeof(int)) {
        return 0;
    }
    int value = 0;
    memcpy(&value, data, size);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create a pcap_t handle
    char* device_name = fuzzInputToString(data, size / 4, 256);
    if (!device_name) {
        return 0; // Invalid input
    }
    pcap_t* pcap = pcap_create(device_name, errbuf);
    free(device_name);
    if (!pcap) {
        return 0; // Failed to create pcap handle
    }

    // Set timeout
    int timeout = fuzzInputToInt(data + size / 4, size / 4);
    if (pcap_set_timeout(pcap, timeout) != 0) {
        pcap_close(pcap);
        return 0; // Failed to set timeout
    }

    // Set snaplen
    int snaplen = fuzzInputToInt(data + size / 2, size / 4);
    if (pcap_set_snaplen(pcap, snaplen) != 0) {
        pcap_close(pcap);
        return 0; // Failed to set snaplen
    }

    // Set datalink
    int datalink = fuzzInputToInt(data + 3 * size / 4, size / 4);
    if (pcap_set_datalink(pcap, datalink) != 0) {
        pcap_close(pcap);
        return 0; // Failed to set datalink
    }

    // Set promiscuous mode
    int promisc = fuzzInputToInt(data + size - 1, 1);
    if (pcap_set_promisc(pcap, promisc) != 0) {
        pcap_close(pcap);
        return 0; // Failed to set promiscuous mode
    }

    // Clean up
    pcap_close(pcap);
    return 0;
}
