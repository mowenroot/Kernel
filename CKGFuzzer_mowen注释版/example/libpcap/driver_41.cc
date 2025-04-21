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

// Function to safely create a pcap_t object
std::unique_ptr<pcap_t, void(*)(pcap_t*)> safe_pcap_create(const char* device, char* errbuf) {
    pcap_t* p = pcap_create(device, errbuf);
    return std::unique_ptr<pcap_t, void(*)(pcap_t*)>(p, [](pcap_t* p) { pcap_close(p); });
}

// Function to safely create a bpf_program object
std::unique_ptr<bpf_program, void(*)(bpf_program*)> safe_bpf_program_create() {
    bpf_program* prog = (bpf_program*)malloc(sizeof(bpf_program));
    return std::unique_ptr<bpf_program, void(*)(bpf_program*)>(prog, [](bpf_program* prog) { pcap_freecode(prog); free(prog); });
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Create a pcap_t object
    auto pcap = safe_pcap_create("any", errbuf);
    if (!pcap) return 0;

    // Set timestamp precision
    int tstamp_precision = data[0] % 2; // 0 for microseconds, 1 for nanoseconds
    if (pcap_set_tstamp_precision(pcap.get(), tstamp_precision) != 0) {
        return 0;
    }

    // Set protocol (Linux specific)
    int protocol = data[1];
    if (pcap_set_protocol_linux(pcap.get(), protocol) != 0) {
        return 0;
    }

    // Compile a filter expression
    auto filter_expr = safe_strndup(data + 2, size - 2);
    if (!filter_expr) return 0;

    auto bpf_prog = safe_bpf_program_create();
    if (!bpf_prog) return 0;

    if (pcap_compile(pcap.get(), bpf_prog.get(), filter_expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        return 0;
    }

    // Open a dump file
    auto dump_file = pcap_dump_open(pcap.get(), "output_file");
    if (!dump_file) return 0;

    // Clean up
    pcap_dump_close(dump_file);
    free(filter_expr);

    return 0;
}
