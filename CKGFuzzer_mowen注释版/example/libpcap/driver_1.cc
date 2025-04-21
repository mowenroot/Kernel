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

// Function to safely allocate memory for bpf_program
struct bpf_program* safe_bpf_program_alloc() {
    struct bpf_program* program = (struct bpf_program*)malloc(sizeof(struct bpf_program));
    if (!program) return nullptr;
    program->bf_len = 0;
    program->bf_insns = nullptr;
    return program;
}

// Function to safely allocate memory for pcap_pkthdr
struct pcap_pkthdr* safe_pcap_pkthdr_alloc() {
    struct pcap_pkthdr* hdr = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    if (!hdr) return nullptr;
    memset(hdr, 0, sizeof(struct pcap_pkthdr));
    return hdr;
}

// Function to safely allocate memory for pcap_data
const u_char* safe_pcap_data_alloc(size_t size) {
    const u_char* data = (const u_char*)malloc(size);
    if (!data) return nullptr;
    memset((void*)data, 0, size);
    return data;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize variables
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Allocate memory for bpf_program
    std::unique_ptr<struct bpf_program> program(safe_bpf_program_alloc());
    if (!program) return 0;

    // Allocate memory for pcap_pkthdr
    std::unique_ptr<struct pcap_pkthdr> hdr(safe_pcap_pkthdr_alloc());
    if (!hdr) return 0;

    // Allocate memory for pcap_data
    std::unique_ptr<const u_char> pkt_data(safe_pcap_data_alloc(size));
    if (!pkt_data) return 0;

    // Safely copy filter expression from fuzz input
    char* filter_exp = safe_strndup(data, size / 2);
    if (!filter_exp) return 0;

    // Open a pcap file for offline reading
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        free(filter_exp);
        return 0;
    }

    // Open the pcap file using pcap_fopen_offline
    pcap_t* p = pcap_fopen_offline(fp, errbuf);
    if (!p) {
        fclose(fp);
        free(filter_exp);
        return 0;
    }

    // Compile the filter expression
    int compile_result = pcap_compile(p, program.get(), filter_exp, 1, PCAP_NETMASK_UNKNOWN);
    if (compile_result != 0) {
        pcap_freecode(program.get());
        pcap_close(p);
        fclose(fp);
        free(filter_exp);
        return 0;
    }

    // Set the filter
    int setfilter_result = pcap_setfilter(p, program.get());
    if (setfilter_result != 0) {
        pcap_freecode(program.get());
        pcap_close(p);
        fclose(fp);
        free(filter_exp);
        return 0;
    }

    // Capture the next packet
    struct pcap_pkthdr* hdr_ptr = hdr.get();
    const u_char* pkt_data_ptr = pkt_data.get();
    int next_ex_result = pcap_next_ex(p, &hdr_ptr, &pkt_data_ptr);
    if (next_ex_result < 0) {
        pcap_freecode(program.get());
        pcap_close(p);
        fclose(fp);
        free(filter_exp);
        return 0;
    }

    // Clean up
    pcap_freecode(program.get());
    pcap_close(p);
    fclose(fp);
    free(filter_exp);

    return 0;
}
