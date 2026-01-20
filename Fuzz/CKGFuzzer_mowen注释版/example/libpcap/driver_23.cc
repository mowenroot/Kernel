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

// Function to create a FILE* from the fuzzer input data
FILE* create_file_from_data(const uint8_t* data, size_t size) {
    // Create a temporary file
    FILE* fp = tmpfile();
    if (!fp) {
        return nullptr;
    }

    // Write the fuzzer input data to the temporary file
    size_t written = fwrite(data, 1, size, fp);
    if (written != size) {
        fclose(fp);
        return nullptr;
    }

    // Rewind the file pointer to the beginning
    rewind(fp);
    return fp;
}

// Function to safely close the FILE*
void safe_fclose(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Function to safely free the pcap_t*
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

    // Create a FILE* from the fuzzer input data
    FILE* fp = create_file_from_data(data, size);
    if (!fp) {
        return 0;
    }

    // Use a unique_ptr to manage the pcap_t* and ensure it is properly closed
    std::unique_ptr<pcap_t, decltype(&safe_pcap_close)> pcap_handle(nullptr, safe_pcap_close);

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file with the specified timestamp precision
    pcap_handle.reset(pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf));
    if (!pcap_handle) {
        safe_fclose(fp);
        return 0;
    }

    // Set the timestamp precision
    int tstamp_precision = (data[0] % 2 == 0) ? PCAP_TSTAMP_PRECISION_MICRO : PCAP_TSTAMP_PRECISION_NANO;
    if (pcap_set_tstamp_precision(pcap_handle.get(), tstamp_precision) != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Set the protocol (Linux specific)
    int protocol = data[1] % 256; // Assuming protocol is a byte value
    if (pcap_set_protocol_linux(pcap_handle.get(), protocol) != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Set the timeout
    int timeout_ms = (data[2] % 1000) + 1; // Timeout between 1ms and 1000ms
    if (pcap_set_timeout(pcap_handle.get(), timeout_ms) != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Set the data link type
    int dlt = data[3] % 256; // Assuming DLT is a byte value
    if (pcap_set_datalink(pcap_handle.get(), dlt) != 0) {
        safe_fclose(fp);
        return 0;
    }

    // Close the file pointer
    safe_fclose(fp);

    return 0;
}
