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

// Function to safely close a file pointer
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Function to safely free a pcap_t pointer
void safe_pcap_close(pcap_t* p) {
    if (p) {
        pcap_close(p);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(uint32_t) + sizeof(int) * 3) {
        return 0;
    }

    // Extract parameters from the fuzz input
    uint32_t precision = *reinterpret_cast<const uint32_t*>(data);
    int timeout_ms = *reinterpret_cast<const int*>(data + sizeof(uint32_t));
    int tstamp_type = *reinterpret_cast<const int*>(data + sizeof(uint32_t) + sizeof(int));
    int snaplen = *reinterpret_cast<const int*>(data + sizeof(uint32_t) + 2 * sizeof(int));

    // Create a temporary file for the fuzzing process
    FILE* fp = tmpfile();
    if (!fp) {
        return 0;
    }

    // Write the fuzz input data to the temporary file
    size_t written = fwrite(data, 1, size, fp);
    if (written != size) {
        safe_fclose(fp);
        return 0;
    }

    // Rewind the file pointer to the beginning
    rewind(fp);

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for offline reading
    std::unique_ptr<pcap_t, decltype(&safe_pcap_close)> pcap(
        pcap_fopen_offline_with_tstamp_precision(fp, precision, errbuf),
        safe_pcap_close
    );

    if (!pcap) {
        safe_fclose(fp);
        return 0;
    }

    // Set timeout
    int result = pcap_set_timeout(pcap.get(), timeout_ms);
    if (result != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Set timestamp type
    result = pcap_set_tstamp_type(pcap.get(), tstamp_type);
    if (result != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Set snapshot length
    result = pcap_set_snaplen(pcap.get(), snaplen);
    if (result != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Get timestamp precision
    int precision_result = pcap_get_tstamp_precision(pcap.get());
    if (precision_result < 0) {
        safe_fclose(fp);
        return 0;
    }

    // Clean up
    safe_fclose(fp);
    return 0;
}
