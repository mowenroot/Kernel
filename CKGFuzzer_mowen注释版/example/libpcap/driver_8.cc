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

// Function to safely allocate memory for a pcap_t object
std::unique_ptr<pcap_t, void(*)(pcap_t*)> safe_pcap_alloc(pcap_t* p) {
    return std::unique_ptr<pcap_t, void(*)(pcap_t*)>(p, [](pcap_t* p) {
        if (p) pcap_close(p);
    });
}

// Function to safely allocate memory for a pcap_dumper_t object
std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)> safe_pcap_dumper_alloc(pcap_dumper_t* d) {
    return std::unique_ptr<pcap_dumper_t, void(*)(pcap_dumper_t*)>(d, [](pcap_dumper_t* d) {
        if (d) pcap_dump_close(d);
    });
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for all operations
    if (size < 10) return 0;

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Extract device name from fuzz input
    size_t device_name_len = data[0];
    if (device_name_len >= size) return 0;
    char* device_name = safe_strndup(data + 1, device_name_len);
    if (!device_name) return 0;

    // Extract protocol value from fuzz input
    int protocol = data[device_name_len + 1];

    // Extract immediate mode value from fuzz input
    int immediate_mode = data[device_name_len + 2];

    // Extract timestamp precision value from fuzz input
    u_int precision = data[device_name_len + 3];

    // Open an offline pcap file with the specified timestamp precision
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        free(device_name);
        return 0;
    }
    auto pcap = safe_pcap_alloc(pcap_fopen_offline_with_tstamp_precision(fp, precision, errbuf));
    if (!pcap) {
        fclose(fp);
        free(device_name);
        return 0;
    }

    // Set the protocol for the pcap handle
    if (pcap_set_protocol_linux(pcap.get(), protocol) != 0) {
        free(device_name);
        return 0;
    }

    // Set immediate mode for the pcap handle
    if (pcap_set_immediate_mode(pcap.get(), immediate_mode) != 0) {
        free(device_name);
        return 0;
    }

    // Lookup the network address and netmask for the device
    bpf_u_int32 netp, maskp;
    if (pcap_lookupnet(device_name, &netp, &maskp, errbuf) != 0) {
        free(device_name);
        return 0;
    }

    // Open a dump file for writing
    auto dumper = safe_pcap_dumper_alloc(pcap_dump_open(pcap.get(), "output_file"));
    if (!dumper) {
        free(device_name);
        return 0;
    }

    // Get the current file position in the dump file
    long file_position = pcap_dump_ftell(dumper.get());
    if (file_position < 0) {
        free(device_name);
        return 0;
    }

    // Clean up
    free(device_name);
    return 0;
}
