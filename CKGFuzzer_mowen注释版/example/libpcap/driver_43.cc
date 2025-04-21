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
void safe_fclose(FILE*& fp) {
    if (fp) {
        fclose(fp);
        fp = nullptr;
    }
}

// Function to safely free a pcap_t pointer
void safe_pcap_close(pcap_t*& p) {
    if (p) {
        pcap_close(p);
        p = nullptr;
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < sizeof(uint32_t) || size > 1024 * 1024) {
        return 0;
    }

    // Create a temporary file for the fuzzing process
    FILE* temp_file = tmpfile();
    if (!temp_file) {
        return 0;
    }

    // Write the fuzz input to the temporary file
    size_t written = fwrite(data, 1, size, temp_file);
    if (written != size) {
        safe_fclose(temp_file);
        return 0;
    }

    // Rewind the file pointer to the beginning
    rewind(temp_file);

    // Buffer to hold the packet data
    std::unique_ptr<uint8_t[]> packet_buffer(new uint8_t[size]);
    memcpy(packet_buffer.get(), data, size);

    // Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Open the temporary file for offline reading
    pcap_t* pcap = pcap_fopen_offline_with_tstamp_precision(temp_file, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!pcap) {
        safe_fclose(temp_file);
        return 0;
    }

    // Set the timestamp precision
    int tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;
    if (pcap_set_tstamp_precision(pcap, tstamp_precision) != 0) {
        safe_pcap_close(pcap);
        safe_fclose(temp_file);
        return 0;
    }

    // Set the protocol for Linux
    int protocol = 0; // Example protocol value
    if (pcap_set_protocol_linux(pcap, protocol) != 0) {
        safe_pcap_close(pcap);
        safe_fclose(temp_file);
        return 0;
    }

    // Set the snapshot length
    int snaplen = 65535; // Example snaplen value
    if (pcap_set_snaplen(pcap, snaplen) != 0) {
        safe_pcap_close(pcap);
        safe_fclose(temp_file);
        return 0;
    }

    // Inject the packet
    int result = pcap_inject(pcap, packet_buffer.get(), size);
    if (result == PCAP_ERROR) {
        safe_pcap_close(pcap);
        safe_fclose(temp_file);
        return 0;
    }

    // Clean up resources
    safe_pcap_close(pcap);
    safe_fclose(temp_file);

    return 0;
}
