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

// Function to safely allocate memory for a structure
template <typename T>
T* safe_malloc() {
    T* ptr = (T*)malloc(sizeof(T));
    if (!ptr) return nullptr;
    memset(ptr, 0, sizeof(T));
    return ptr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Allocate and initialize necessary structures
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, maskp;
    pcap_t* pcap = nullptr;
    pcap_dumper_t* dumper = nullptr;
    struct bpf_program bpf_prog;
    FILE* fp = nullptr;

    // Safely extract strings from fuzz input
    char* device = safe_strndup(data, size / 4);
    char* input_file = safe_strndup(data + size / 4, size / 4);
    char* output_file = safe_strndup(data + size / 2, size / 4);
    char* filter_exp = safe_strndup(data + 3 * size / 4, size / 4);

    // Ensure all strings are valid
    if (!device || !input_file || !output_file || !filter_exp) {
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Step 1: pcap_lookupnet
    if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1) {
        // Handle error
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Step 2: pcap_fopen_offline_with_tstamp_precision
    fp = fopen(input_file, "rb");
    if (!fp) {
        // Handle error
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }
    pcap = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        // Handle error
        fclose(fp);
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Step 3: pcap_set_protocol_linux
    if (pcap_set_protocol_linux(pcap, 0) == PCAP_ERROR_ACTIVATED) {
        // Handle error
        pcap_close(pcap);
        fclose(fp);
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Step 4: pcap_compile
    if (pcap_compile(pcap, &bpf_prog, filter_exp, 1, maskp) == -1) {
        // Handle error
        pcap_close(pcap);
        fclose(fp);
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Step 5: pcap_dump_open_append
    dumper = pcap_dump_open_append(pcap, output_file);
    if (!dumper) {
        // Handle error
        pcap_close(pcap);
        fclose(fp);
        free(device);
        free(input_file);
        free(output_file);
        free(filter_exp);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    fclose(fp);
    pcap_dump_close(dumper);
    free(device);
    free(input_file);
    free(output_file);
    free(filter_exp);

    return 0;
}
