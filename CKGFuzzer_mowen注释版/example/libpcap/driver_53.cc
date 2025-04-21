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

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Extract device name from fuzz input
    size_t device_name_len = data[0];
    if (device_name_len >= size) return 0;
    char* device_name = safe_strndup(data + 1, device_name_len);
    if (!device_name) return 0;

    // Extract timestamp precision and type from fuzz input
    int tstamp_precision = safe_atoi(data + 1 + device_name_len, 4);
    int tstamp_type = safe_atoi(data + 1 + device_name_len + 4, 4);

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Step 1: Call pcap_lookupnet
    bpf_u_int32 netp = 0, maskp = 0;
    int lookup_result = pcap_lookupnet(device_name, &netp, &maskp, errbuf);
    if (lookup_result == -1) {
        free(device_name);
        return 0; // Error in pcap_lookupnet
    }

    // Step 2: Open a file for offline reading
    FILE* fp = fopen("input_file", "rb");
    if (!fp) {
        free(device_name);
        return 0; // Error opening file
    }

    // Step 3: Call pcap_fopen_offline_with_tstamp_precision
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(fp, tstamp_precision, errbuf);
    if (!pcap) {
        fclose(fp);
        free(device_name);
        return 0; // Error in pcap_fopen_offline_with_tstamp_precision
    }

    // Step 4: Set timestamp precision
    int set_precision_result = pcap_set_tstamp_precision(pcap, tstamp_precision);
    if (set_precision_result != 0) {
        pcap_close(pcap);
        fclose(fp);
        free(device_name);
        return 0; // Error in pcap_set_tstamp_precision
    }

    // Step 5: Set timestamp type
    int set_type_result = pcap_set_tstamp_type(pcap, tstamp_type);
    if (set_type_result != 0) {
        pcap_close(pcap);
        fclose(fp);
        free(device_name);
        return 0; // Error in pcap_set_tstamp_type
    }

    // Step 6: Capture the next packet
    struct pcap_pkthdr* pkt_header = nullptr;
    const u_char* pkt_data = nullptr;
    int next_ex_result = pcap_next_ex(pcap, &pkt_header, &pkt_data);
    if (next_ex_result < 0) {
        pcap_close(pcap);
        fclose(fp);
        free(device_name);
        return 0; // Error in pcap_next_ex
    }

    // Clean up
    pcap_close(pcap);
    fclose(fp);
    free(device_name);

    return 0;
}
