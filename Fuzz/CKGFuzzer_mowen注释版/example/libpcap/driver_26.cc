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
#include <errno.h> // Include errno.h for strerror

// Function to safely convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size, char* errbuf) {
    if (size == 0) {
        strncpy(errbuf, "Empty input", PCAP_ERRBUF_SIZE);
        return nullptr;
    }
    char* str = (char*)malloc(size + 1);
    if (!str) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "malloc: %s", strerror(errno)); // Use snprintf to format error message
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int fuzzInputToInt(const uint8_t* data, size_t size, char* errbuf) {
    if (size == 0) {
        strncpy(errbuf, "Empty input", PCAP_ERRBUF_SIZE);
        return -1;
    }
    // Ensure the input is within the range of an integer
    if (size > sizeof(int)) {
        strncpy(errbuf, "Input too large", PCAP_ERRBUF_SIZE);
        return -1;
    }
    int value = 0;
    memcpy(&value, data, size);
    return value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // Safely convert fuzz input to a string for device name
    char* device_name = fuzzInputToString(data, size / 2, errbuf);
    if (!device_name) {
        return 0;
    }

    // Safely convert fuzz input to an integer for timestamp precision
    int tstamp_precision = fuzzInputToInt(data + size / 2, size / 2, errbuf);
    if (tstamp_precision == -1) {
        free(device_name);
        return 0;
    }

    // Create a pcap handle
    pcap_t* pcap = pcap_create(device_name, errbuf);
    if (!pcap) {
        free(device_name);
        return 0;
    }

    // Set timestamp precision
    int result = pcap_set_tstamp_precision(pcap, tstamp_precision);
    if (result != 0) {
        pcap_close(pcap);
        free(device_name);
        return 0;
    }

    // Set datalink type (use a fixed DLT for simplicity)
    result = pcap_set_datalink(pcap, DLT_EN10MB);
    if (result != 0) {
        pcap_close(pcap);
        free(device_name);
        return 0;
    }

    // Open an offline pcap file (use a fixed file name for simplicity)
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        pcap_close(pcap);
        free(device_name);
        return 0;
    }

    pcap_t* offline_pcap = pcap_fopen_offline(fp, errbuf);
    if (!offline_pcap) {
        fclose(fp);
        pcap_close(pcap);
        free(device_name);
        return 0;
    }

    // Retrieve statistics
    struct pcap_stat stats;
    result = pcap_stats(pcap, &stats);
    if (result != 0) {
        pcap_close(offline_pcap);
        fclose(fp);
        pcap_close(pcap);
        free(device_name);
        return 0;
    }

    // Clean up
    pcap_close(offline_pcap);
    fclose(fp);
    pcap_close(pcap);
    free(device_name);

    return 0;
}
