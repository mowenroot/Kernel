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
char* fuzz_input_to_string(const uint8_t* data, size_t size, char* errbuf) {
    if (size == 0) {
        strncpy(errbuf, "Input size is zero", PCAP_ERRBUF_SIZE);
        return nullptr;
    }
    char* str = (char*)malloc(size + 1);
    if (!str) {
        strncpy(errbuf, "Memory allocation failed", PCAP_ERRBUF_SIZE);
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int fuzz_input_to_int(const uint8_t* data, size_t size, char* errbuf) {
    if (size < sizeof(int)) {
        strncpy(errbuf, "Input size is too small for an integer", PCAP_ERRBUF_SIZE);
        return -1;
    }
    int value;
    memcpy(&value, data, sizeof(int));
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = nullptr;
    char* device_name = nullptr;
    int rfmon, snaplen, datalink, tstamp_type;

    // Initialize error buffer
    memset(errbuf, 0, sizeof(errbuf));

    // Convert fuzz input to a device name string
    device_name = fuzz_input_to_string(data, size / 4, errbuf);
    if (!device_name) {
        return 0;
    }

    // Create a pcap handle
    pcap_handle = pcap_create(device_name, errbuf);
    if (!pcap_handle) {
        free(device_name);
        return 0;
    }

    // Set monitor mode
    rfmon = fuzz_input_to_int(data + size / 4, size / 4, errbuf);
    if (pcap_set_rfmon(pcap_handle, rfmon) != 0) {
        pcap_close(pcap_handle);
        free(device_name);
        return 0;
    }

    // Set snapshot length
    snaplen = fuzz_input_to_int(data + 2 * size / 4, size / 4, errbuf);
    if (pcap_set_snaplen(pcap_handle, snaplen) != 0) {
        pcap_close(pcap_handle);
        free(device_name);
        return 0;
    }

    // Set data link type
    datalink = fuzz_input_to_int(data + 3 * size / 4, size / 4, errbuf);
    if (pcap_set_datalink(pcap_handle, datalink) != 0) {
        pcap_close(pcap_handle);
        free(device_name);
        return 0;
    }

    // Set timestamp type
    tstamp_type = fuzz_input_to_int(data + 4 * size / 4, size / 4, errbuf);
    if (pcap_set_tstamp_type(pcap_handle, tstamp_type) != 0) {
        pcap_close(pcap_handle);
        free(device_name);
        return 0;
    }

    // Clean up
    pcap_close(pcap_handle);
    free(device_name);

    return 0;
}
