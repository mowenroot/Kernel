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
#include <cstring>
#include <cerrno>

// Function to safely allocate memory and return a unique_ptr
template <typename T>
std::unique_ptr<T> safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        throw std::bad_alloc();
    }
    return std::unique_ptr<T>(ptr);
}

// Function to safely copy data into a buffer
void safe_copy(void* dest, const void* src, size_t size) {
    if (memcpy(dest, src, size) != dest) {
        throw std::runtime_error("Memory copy failed");
    }
}

// Function to safely open a file
FILE* safe_fopen(const char* filename, const char* mode) {
    FILE* fp = fopen(filename, mode);
    if (!fp) {
        throw std::runtime_error("Failed to open file");
    }
    return fp;
}

// Function to safely close a file
void safe_fclose(FILE* fp) {
    if (fclose(fp) != 0) {
        throw std::runtime_error("Failed to close file");
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(int) * 3 + sizeof(uint8_t) * 100) {
        return 0;
    }

    // Extract parameters from the fuzz input
    int immediate_mode = *reinterpret_cast<const int*>(data);
    int protocol = *reinterpret_cast<const int*>(data + sizeof(int));
    int tstamp_type = *reinterpret_cast<const int*>(data + 2 * sizeof(int));
    const uint8_t* packet_data = data + 3 * sizeof(int);
    size_t packet_size = size - 3 * sizeof(int);

    // Allocate memory for error buffer
    auto errbuf = safe_malloc<char>(PCAP_ERRBUF_SIZE);

    // Open a file for offline reading
    FILE* fp = safe_fopen("input_file", "rb");
    std::unique_ptr<FILE, decltype(&safe_fclose)> file_guard(fp, safe_fclose);

    // Open the pcap handle for offline reading
    pcap_t* p = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf.get());
    if (!p) {
        return 0;
    }
    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_guard(p, pcap_close);

    // Set immediate mode
    if (pcap_set_immediate_mode(p, immediate_mode) != 0) {
        return 0;
    }

    // Set protocol
    if (pcap_set_protocol_linux(p, protocol) != 0) {
        return 0;
    }

    // Set timestamp type
    if (pcap_set_tstamp_type(p, tstamp_type) != 0) {
        return 0;
    }

    // Send packet
    if (pcap_sendpacket(p, packet_data, packet_size) != 0) {
        return 0;
    }

    return 0;
}
