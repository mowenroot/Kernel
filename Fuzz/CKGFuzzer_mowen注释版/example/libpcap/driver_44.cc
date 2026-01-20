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
#include <fstream>

// Function to create a temporary file and write fuzzer input to it
std::unique_ptr<FILE, decltype(&fclose)> create_temp_file(const uint8_t *data, size_t size) {
    FILE *fp = tmpfile();
    if (!fp) {
        return {nullptr, fclose};
    }
    fwrite(data, 1, size, fp);
    rewind(fp);
    return {fp, fclose};
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a temporary file with the fuzzer input
    auto file = create_temp_file(data, size);
    if (!file) {
        return 0;
    }

    // Buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for offline reading
    pcap_t *pcap = pcap_fopen_offline(file.get(), errbuf);
    if (!pcap) {
        return 0;
    }

    // Set monitor mode (rfmon)
    int rfmon = data[0] % 2; // Use the first byte of input to determine rfmon
    int result = pcap_set_rfmon(pcap, rfmon);
    if (result != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set protocol for Linux
    int protocol = data[1] % 256; // Use the second byte of input to determine protocol
    result = pcap_set_protocol_linux(pcap, protocol);
    if (result != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Set snapshot length
    int snaplen = data[2] % 65536; // Use the third byte of input to determine snaplen
    result = pcap_set_snaplen(pcap, snaplen);
    if (result != 0) {
        pcap_close(pcap);
        return 0;
    }

    // Close the pcap handle
    pcap_close(pcap);

    // Retrieve and print the libpcap library version (for informational purposes)
    const char *version = pcap_lib_version();
    (void)version; // Suppress unused variable warning

    return 0;
}
