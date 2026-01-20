#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Callback function for ares_search_dnsrec
void dnsrec_callback(void *arg, ares_status_t status, int timeouts, ares_dns_record_t *dnsrec) {
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, 0x1234, 0x0100, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Parse the input data into a DNS record
    status = ares_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Perform a DNS record search
    status = ares_search_dnsrec(channel, dnsrec, dnsrec_callback, NULL);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    ares_destroy(channel);

    return 0;
}
