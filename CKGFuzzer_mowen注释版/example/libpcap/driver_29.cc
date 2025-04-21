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
#include <cstddef>
#include <memory>

// Function to safely allocate memory for a structure
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_copy(void* dest, const void* src, size_t size) {
    if (memcpy(dest, src, size) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(EXIT_FAILURE);
    }
}

// Function to safely set memory
void safe_set(void* dest, int value, size_t size) {
    if (memset(dest, value, size) != dest) {
        fprintf(stderr, "Memory set failed\n");
        exit(EXIT_FAILURE);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(struct pcap_pkthdr) + 1) {
        return 0;
    }

    // Initialize pcap_t and pcap_dumper_t
    pcap_t* pcap = nullptr;
    pcap_dumper_t* dumper = nullptr;

    // Allocate memory for pcap_pkthdr and packet data
    auto pkthdr = std::unique_ptr<struct pcap_pkthdr>(safe_malloc<struct pcap_pkthdr>(sizeof(struct pcap_pkthdr)));
    auto packet = std::unique_ptr<uint8_t[]>(safe_malloc<uint8_t>(size - sizeof(struct pcap_pkthdr)));

    // Copy data to pcap_pkthdr and packet
    safe_copy(pkthdr.get(), data, sizeof(struct pcap_pkthdr));
    safe_copy(packet.get(), data + sizeof(struct pcap_pkthdr), size - sizeof(struct pcap_pkthdr));

    // Open a dummy pcap handle (not activated)
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        fprintf(stderr, "Failed to open dummy pcap handle\n");
        return 0;
    }

    // Open a dump file
    dumper = pcap_dump_open(pcap, "output_file");
    if (!dumper) {
        fprintf(stderr, "Failed to open dump file\n");
        pcap_close(pcap);
        return 0;
    }

    // Dump the packet
    pcap_dump(reinterpret_cast<u_char*>(dumper), pkthdr.get(), packet.get());

    // Flush the dump file
    if (pcap_dump_flush(dumper) != 0) {
        fprintf(stderr, "Failed to flush dump file\n");
    }

    // Close the dump file
    pcap_dump_close(dumper);

    // Close the dummy pcap handle
    pcap_close(pcap);

    return 0;
}
