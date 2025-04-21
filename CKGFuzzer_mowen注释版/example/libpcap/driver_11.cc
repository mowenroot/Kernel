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

// Function to safely create a FILE* from the fuzz input data
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

// Function to safely close the FILE*
void close_file(FILE* fp) {
    if (fp) {
        fclose(fp);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Create a temporary file from the fuzz input data
    FILE* fp = create_file_from_data(data, size);
    if (!fp) {
        return 0;
    }

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Open the pcap file for offline reading
    pcap_t* pcap = pcap_fopen_offline(fp, errbuf);
    if (!pcap) {
        close_file(fp);
        return 0;
    }

    // Set monitor mode (rfmon)
    int rfmon = data[0] % 2; // Use the first byte of the input to determine rfmon
    int rfmon_result = pcap_set_rfmon(pcap, rfmon);
    if (rfmon_result != 0) {
        pcap_close(pcap);
        close_file(fp);
        return 0;
    }

    // Set timeout
    int timeout_ms = (data[1] << 8) | data[2]; // Use the next two bytes for timeout
    int timeout_result = pcap_set_timeout(pcap, timeout_ms);
    if (timeout_result != 0) {
        pcap_close(pcap);
        close_file(fp);
        return 0;
    }

    // Set snapshot length
    int snaplen = (data[3] << 8) | data[4]; // Use the next two bytes for snaplen
    int snaplen_result = pcap_set_snaplen(pcap, snaplen);
    if (snaplen_result != 0) {
        pcap_close(pcap);
        close_file(fp);
        return 0;
    }

    // Retrieve the file descriptor associated with the pcap handle
    int fd = pcap_fileno(pcap);
    if (fd == PCAP_ERROR) {
        pcap_close(pcap);
        close_file(fp);
        return 0;
    }

    // Clean up
    pcap_close(pcap);
    close_file(fp);

    return 0;
}
