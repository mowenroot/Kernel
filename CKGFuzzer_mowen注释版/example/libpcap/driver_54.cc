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

// Function to safely allocate memory for a string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for an integer array
int* safe_intdup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    int* arr = (int*)malloc(size);
    if (!arr) return nullptr;
    memcpy(arr, data, size);
    return arr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(int) * 3) return 0;

    // Extract necessary data from the fuzz input
    int protocol = *reinterpret_cast<const int*>(data);
    int tstamp_type = *reinterpret_cast<const int*>(data + sizeof(int));
    int precision = *reinterpret_cast<const int*>(data + 2 * sizeof(int));

    // Create a temporary file for pcap_fopen_offline_with_tstamp_precision
    FILE* temp_file = tmpfile();
    if (!temp_file) return 0;

    // Open the pcap handle with the temporary file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(temp_file, precision, errbuf);
    if (!pcap) {
        fclose(temp_file);
        return 0;
    }

    // Set the protocol for the pcap handle
    int set_protocol_result = pcap_set_protocol_linux(pcap, protocol);
    if (set_protocol_result != 0) {
        pcap_close(pcap);
        fclose(temp_file);
        return 0;
    }

    // Set the timestamp type for the pcap handle
    int set_tstamp_result = pcap_set_tstamp_type(pcap, tstamp_type);
    if (set_tstamp_result != 0) {
        pcap_close(pcap);
        fclose(temp_file);
        return 0;
    }

    // List the datalinks supported by the pcap handle
    int* datalinks = nullptr;
    int datalink_count = pcap_list_datalinks(pcap, &datalinks);
    if (datalink_count <= 0) {
        free(datalinks);
        pcap_close(pcap);
        fclose(temp_file);
        return 0;
    }

    // Create a dummy packet header and packet data for pcap_offline_filter
    struct pcap_pkthdr pkthdr;
    pkthdr.len = size;
    pkthdr.caplen = size;
    const uint8_t* packet_data = data + 3 * sizeof(int);

    // Apply the offline filter to the dummy packet
    struct bpf_program bpf;
    bpf.bf_insns = reinterpret_cast<struct bpf_insn*>(const_cast<uint8_t*>(packet_data));
    int filter_result = pcap_offline_filter(&bpf, &pkthdr, packet_data);

    // Clean up resources
    free(datalinks);
    pcap_close(pcap);
    fclose(temp_file);

    return 0;
}
