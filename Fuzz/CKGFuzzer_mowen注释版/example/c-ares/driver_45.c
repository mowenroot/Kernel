#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle the callback for ares_getnameinfo
void nameinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *addrinfo) {
    if (addrinfo) {
        ares_freeaddrinfo(addrinfo);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the operations
    if (size < sizeof(struct sockaddr) + 2 * sizeof(unsigned short)) {
        return 0;
    }

    // Initialize variables
    ares_channel_t *channel = NULL; // Change to pointer type to avoid incomplete type error
    ares_dns_record_t *dnsrec = NULL;
    struct sockaddr sa;
    unsigned short id, flags;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;

    // Extract values from fuzz input
    memcpy(&sa, data, sizeof(struct sockaddr));
    memcpy(&id, data + sizeof(struct sockaddr), sizeof(unsigned short));
    memcpy(&flags, data + sizeof(struct sockaddr) + sizeof(unsigned short), sizeof(unsigned short));
    opcode = (ares_dns_opcode_t)(data[sizeof(struct sockaddr) + 2 * sizeof(unsigned short)] % 16); // Replace with actual max value
    rcode = (ares_dns_rcode_t)(data[sizeof(struct sockaddr) + 2 * sizeof(unsigned short) + 1] % 16); // Replace with actual max value

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Set local device name
    if (size > sizeof(struct sockaddr) + 2 * sizeof(unsigned short) + 2) {
        ares_set_local_dev(channel, (const char *)(data + sizeof(struct sockaddr) + 2 * sizeof(unsigned short) + 2));
    }

    // Create DNS record
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Perform getnameinfo operation
    ares_getnameinfo(channel, &sa, sizeof(sa), 0, nameinfo_callback, NULL);

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    ares_destroy(channel);

    return 0;
}
