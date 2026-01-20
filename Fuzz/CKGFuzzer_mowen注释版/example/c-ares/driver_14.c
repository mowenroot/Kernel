#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Callback function for ares_search_dnsrec
void dummy_callback(void *arg, ares_status_t status, int timeouts, ares_dns_record_t *dnsrec) {
    // This is a dummy callback function for the fuzz driver
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t) + 1) {
        return 0;
    }

    // Extract parameters from the fuzz input
    unsigned short id = *(unsigned short *)data;
    unsigned short flags = *(unsigned short *)(data + sizeof(unsigned short));
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t *)(data + sizeof(unsigned short) * 2);
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t));
    const char *rec_type_str = (const char *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t));

    // Create a DNS record
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Convert DNS record type string to enum
    ares_dns_rec_type_t rec_type;
    if (!ares_dns_rec_type_fromstr(&rec_type, rec_type_str)) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Perform a DNS record search (dummy channel and callback)
    ares_channel_t *dummy_channel = NULL; // Use a pointer to ares_channel_t
    if (ares_init(&dummy_channel) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    status = ares_search_dnsrec(dummy_channel, dnsrec, dummy_callback, NULL);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(dummy_channel);
        return 0;
    }

    // Retrieve an address from the DNS record (dummy key)
    ares_dns_rr_key_t dummy_key = 0; // Dummy key for fuzzing
    const struct in_addr *addr = ares_dns_rr_get_addr(dnsrec, dummy_key);
    if (addr == NULL) {
        ares_dns_record_destroy(dnsrec);
        ares_destroy(dummy_channel);
        return 0;
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    ares_destroy(dummy_channel);
    return 0;
}
