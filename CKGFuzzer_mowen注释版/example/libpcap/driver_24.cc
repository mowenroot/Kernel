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

// Function to safely convert fuzz input to a string
const char* safe_data_to_string(const uint8_t* data, size_t size, char* buffer, size_t buffer_size) {
    size_t len = size < buffer_size - 1 ? size : buffer_size - 1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return buffer;
}

// Function to safely convert fuzz input to an integer
int safe_data_to_int(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    return static_cast<int>(data[0]);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize pcap_t and bpf_program
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) return 0;

    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_guard(pcap, pcap_close);

    struct bpf_program bpf_prog;
    memset(&bpf_prog, 0, sizeof(bpf_prog));

    // Buffer for filter expression
    char filter_expr[256];
    const char* filter_str = safe_data_to_string(data, size, filter_expr, sizeof(filter_expr));

    // Compile the filter expression
    if (pcap_compile(pcap, &bpf_prog, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        // Set protocol
        int protocol = safe_data_to_int(data, size);
        if (pcap_set_protocol_linux(pcap, protocol) == 0) {
            // Get timestamp precision
            int tstamp_precision = pcap_get_tstamp_precision(pcap);

            // Set timestamp type
            int tstamp_type = safe_data_to_int(data, size);
            pcap_set_tstamp_type(pcap, tstamp_type);

            // List datalinks
            int* dlt_list = nullptr;
            int dlt_count = pcap_list_datalinks(pcap, &dlt_list);
            if (dlt_count > 0) {
                free(dlt_list);
            }
        }
    }

    // Free the compiled filter program
    pcap_freecode(&bpf_prog);

    return 0;
}
