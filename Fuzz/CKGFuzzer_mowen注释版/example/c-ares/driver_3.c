#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Callback function for ares_search_dnsrec
void dummy_callback(void *arg, ares_status_t status, int timeouts, ares_dns_record_t *dnsrec) {
    // This is a dummy callback function for the fuzz driver.
    // In a real application, this would handle the DNS record result.
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL; // Use a pointer to ares_channel_t
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_status_t status;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Ensure size is within a reasonable limit to prevent excessive memory usage
    if (size < sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t)) {
        ares_destroy(channel);
        return 0;
    }

    // Extract parameters from fuzz input
    unsigned short id = (unsigned short)((data[0] << 8) | data[1]);
    unsigned short flags = (unsigned short)((data[2] << 8) | data[3]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Perform a DNS record search
    status = ares_search_dnsrec(channel, dnsrec_dup, dummy_callback, NULL);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_dns_record_destroy(dnsrec_dup);
        ares_destroy(channel);
        return 0;
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    ares_dns_record_destroy(dnsrec_dup);
    ares_destroy(channel);

    return 0;
}
