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

// Function to safely convert size_t to int
int safe_size_to_int(size_t size) {
    if (size > INT_MAX) {
        return -1;
    }
    return static_cast<int>(size);
}

// Function to safely copy data to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    if (size == 0) {
        return nullptr;
    }
    return malloc(size);
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr != nullptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits
    if (size == 0 || size > 1024 * 1024) {
        return 0;
    }

    // Initialize pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for packet header and data
    std::unique_ptr<pcap_pkthdr> pkthdr(static_cast<pcap_pkthdr*>(safe_malloc(sizeof(pcap_pkthdr))));
    std::unique_ptr<uint8_t[]> packet(new uint8_t[size]);
    if (!pkthdr || !packet) {
        pcap_close(handle);
        return 0;
    }

    // Copy fuzz input to packet buffer
    safe_copy(packet.get(), data, size);

    // Set filter (dummy filter for demonstration)
    bpf_program filter;
    if (pcap_compile(handle, &filter, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        return 0;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        pcap_freecode(&filter);
        pcap_close(handle);
        return 0;
    }
    pcap_freecode(&filter);

    // Inject packet
    if (pcap_inject(handle, packet.get(), size) == -1) {
        pcap_close(handle);
        return 0;
    }

    // Capture packet using pcap_next
    const u_char* captured_packet = pcap_next(handle, pkthdr.get());
    if (captured_packet == nullptr) {
        pcap_close(handle);
        return 0;
    }

    // Capture packet using pcap_next_ex
    struct pcap_pkthdr* next_ex_pkthdr;
    const u_char* next_ex_packet;
    int next_ex_result = pcap_next_ex(handle, &next_ex_pkthdr, &next_ex_packet);
    if (next_ex_result <= 0) {
        pcap_close(handle);
        return 0;
    }

    // Dispatch packets using pcap_dispatch
    int dispatch_result = pcap_dispatch(handle, 1, nullptr, nullptr);
    if (dispatch_result < 0) {
        pcap_close(handle);
        return 0;
    }

    // Loop packets using pcap_loop
    int loop_result = pcap_loop(handle, 1, nullptr, nullptr);
    if (loop_result < 0) {
        pcap_close(handle);
        return 0;
    }

    // Clean up
    pcap_close(handle);
    return 0;
}
