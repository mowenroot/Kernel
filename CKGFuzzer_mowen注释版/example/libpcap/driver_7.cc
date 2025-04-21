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

// Function to safely create a pcap_pkthdr structure
struct pcap_pkthdr create_pcap_pkthdr(const uint8_t* data, size_t size) {
    struct pcap_pkthdr hdr;
    if (size < sizeof(hdr)) {
        memset(&hdr, 0, sizeof(hdr));
    } else {
        memcpy(&hdr, data, sizeof(hdr));
    }
    return hdr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(pcap_pkthdr) + 1) return 0;

    // Create a pcap_pkthdr structure
    struct pcap_pkthdr hdr = create_pcap_pkthdr(data, sizeof(pcap_pkthdr));

    // Create a filename from the input data
    char* filename = safe_strndup(data + sizeof(pcap_pkthdr), size - sizeof(pcap_pkthdr));
    if (!filename) return 0;

    // Open the file for appending
    std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)> dumper_ptr(pcap_dump_open_append(nullptr, filename), [](pcap_dumper_t* d) { pcap_dump_close(d); });
    free(filename);
    if (!dumper_ptr) return 0;

    // Dump the packet
    pcap_dump((u_char*)dumper_ptr.get(), &hdr, data + sizeof(pcap_pkthdr));

    // Flush the dump
    if (pcap_dump_flush(dumper_ptr.get()) != 0) return 0;

    // Retrieve the file pointer and close it manually (for coverage)
    FILE* file = pcap_dump_file(dumper_ptr.get());
    if (file) {
        fclose(file);
    }

    return 0;
}
