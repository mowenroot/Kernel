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
#include <string>  // Added this include to fix the std::string errors

// Function to safely convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    if (size == 0) return "";
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to safely convert fuzz input to an integer
int FuzzInputToInt(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    return static_cast<int>(*data);
}

// Function to safely convert fuzz input to a boolean
bool FuzzInputToBool(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    return *data % 2 == 0;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size > 1024) return 0;

    // Initialize variables
    std::unique_ptr<struct bpf_program> program(new struct bpf_program);
    std::string filter_expression = FuzzInputToString(data, size);
    int optimize = FuzzInputToBool(data, size);
    bpf_u_int32 netmask = FuzzInputToInt(data, size);
    int snaplen = FuzzInputToInt(data, size);
    int linktype = FuzzInputToInt(data, size);

    // Compile the filter expression using pcap_compile_nopcap
    int compile_result = pcap_compile_nopcap(snaplen, linktype, program.get(), filter_expression.c_str(), optimize, netmask);
    if (compile_result != 0) {
        // Handle compilation error
        return 0;
    }

    // Validate the compiled BPF program
    int validate_result = bpf_validate(program->bf_insns, program->bf_len);
    if (validate_result != 0) {
        // Handle validation error
        pcap_freecode(program.get());
        return 0;
    }

    // Generate a human-readable representation of the BPF program
    char* bpf_image_str = bpf_image(program->bf_insns, program->bf_len);
    if (bpf_image_str) {
        // Optionally, print or log the BPF image string for debugging
        // printf("BPF Image: %s\n", bpf_image_str);
    }

    // Free the compiled BPF program
    pcap_freecode(program.get());

    return 0;
}
