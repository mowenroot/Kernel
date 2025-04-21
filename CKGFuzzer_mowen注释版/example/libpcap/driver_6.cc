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
#include <cstdio>

// Function to create a FILE pointer from the fuzz input data
FILE* create_file_from_data(const uint8_t* data, size_t size) {
    // Create a temporary file
    FILE* fp = tmpfile();
    if (!fp) {
        return nullptr;
    }

    // Write the fuzz input data to the temporary file
    size_t written = fwrite(data, 1, size, fp);
    if (written != size) {
        fclose(fp);
        return nullptr;
    }

    // Rewind the file pointer to the beginning
    rewind(fp);
    return fp;
}

// Function to safely close the FILE pointer
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Function to safely free the pcap_t pointer
void safe_pcap_close(pcap_t* p) {
    if (p) {
        pcap_close(p);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Create a FILE pointer from the fuzz input data
    std::unique_ptr<FILE, decltype(&safe_fclose)> fp(create_file_from_data(data, size), safe_fclose);
    if (!fp) {
        return 0;
    }

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for offline reading with timestamp precision
    std::unique_ptr<pcap_t, decltype(&safe_pcap_close)> p(pcap_fopen_offline_with_tstamp_precision(fp.get(), PCAP_TSTAMP_PRECISION_MICRO, errbuf), safe_pcap_close);
    if (!p) {
        return 0;
    }

    // Set the timestamp precision
    int precision_result = pcap_set_tstamp_precision(p.get(), PCAP_TSTAMP_PRECISION_MICRO);
    if (precision_result != 0) {
        return 0;
    }

    // Set the snapshot length
    int snaplen_result = pcap_set_snaplen(p.get(), 65535);
    if (snaplen_result != 0) {
        return 0;
    }

    // Set the data link type
    int datalink_result = pcap_set_datalink(p.get(), DLT_EN10MB);
    if (datalink_result != 0) {
        return 0;
    }

    // Convert the data link type to its name
    const char* datalink_name = pcap_datalink_val_to_name(DLT_EN10MB);
    if (!datalink_name) {
        return 0;
    }

    // If we reach here, all API calls were successful
    return 0;
}
