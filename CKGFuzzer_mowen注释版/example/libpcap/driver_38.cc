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

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a file name from fuzz input
char* create_file_name(const uint8_t* data, size_t size) {
    if (size > 255) size = 255; // Limit file name length
    return safe_strndup(data, size);
}

// Function to safely create a pcap_t handle from fuzz input
std::unique_ptr<pcap_t, void(*)(pcap_t*)> safe_pcap_fopen_offline(const uint8_t* data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE* fp = fmemopen((void*)data, size, "rb");
    if (!fp) return {nullptr, [](pcap_t*){}};
    pcap_t* p = pcap_fopen_offline(fp, errbuf);
    if (!p) {
        fclose(fp);
        return {nullptr, [](pcap_t*){}};
    }
    return {p, [](pcap_t* p) { pcap_close(p); }};
}

// Function to safely create a pcap_dumper_t handle from fuzz input
std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)> safe_pcap_dump_open(pcap_t* p, const uint8_t* data, size_t size) {
    char* fname = create_file_name(data, size);
    if (!fname) return {nullptr, [](pcap_dumper_t*){}};
    pcap_dumper_t* dumper = pcap_dump_open(p, fname);
    free(fname);
    if (!dumper) return {nullptr, [](pcap_dumper_t*){}};
    return {dumper, [](pcap_dumper_t* d) { pcap_dump_close(d); }};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Create a pcap_t handle for offline reading
    auto pcap_handle = safe_pcap_fopen_offline(data, size);
    if (!pcap_handle) return 0;

    // Create a pcap_dumper_t handle for writing
    auto dumper_handle = safe_pcap_dump_open(pcap_handle.get(), data + 8, size - 8);
    if (!dumper_handle) return 0;

    // Set the data link type
    int dlt = data[0];
    if (pcap_set_datalink(pcap_handle.get(), dlt) == -1) return 0;

    // Set the timestamp type
    int tstamp_type = data[1];
    if (pcap_set_tstamp_type(pcap_handle.get(), tstamp_type) == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) return 0;

    // Perform any additional operations or checks here

    return 0;
}
