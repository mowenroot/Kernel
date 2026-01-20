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
char* fuzz_input_to_string(const uint8_t* data, size_t size, size_t* str_size) {
    if (size == 0) {
        *str_size = 0;
        return nullptr;
    }

    // Ensure the input is null-terminated
    *str_size = size;
    char* str = (char*)malloc(*str_size + 1);
    if (!str) {
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int fuzz_input_to_int(const uint8_t* data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Convert the first 4 bytes to an integer
    int value = 0;
    size_t bytes_to_copy = size < sizeof(int) ? size : sizeof(int);
    memcpy(&value, data, bytes_to_copy);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < 4) {
        return 0;
    }

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a pcap handle
    size_t device_name_size;
    char* device_name = fuzz_input_to_string(data, size / 2, &device_name_size);
    if (!device_name) {
        return 0;
    }

    pcap_t* pcap = pcap_create(device_name, errbuf);
    free(device_name);

    if (!pcap) {
        return 0;
    }

    // Set timestamp precision
    int tstamp_precision = fuzz_input_to_int(data + size / 2, size / 2);
    if (pcap_set_tstamp_precision(pcap, tstamp_precision) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set capture direction
    pcap_direction_t direction = static_cast<pcap_direction_t>(fuzz_input_to_int(data, 1));
    if (pcap_setdirection(pcap, direction) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set protocol for Linux
    int protocol = fuzz_input_to_int(data + 1, 1);
    if (pcap_set_protocol_linux(pcap, protocol) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set datalink type
    int dlt = fuzz_input_to_int(data + 2, 2);
    if (pcap_set_datalink(pcap, dlt) != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    return 0;
}
