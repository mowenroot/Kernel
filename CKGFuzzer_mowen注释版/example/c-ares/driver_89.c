#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle errors and cleanup resources
void handle_error(ares_dns_record_t *dnsrec, struct hostent **host) {
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
    if (*host) {
        ares_free(*host);
        *host = NULL;
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    struct hostent *host = NULL;
    int status;

    // Ensure input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Create a DNS record using the fuzzer input
    status = ares_dns_record_create(&dnsrec, (unsigned short)(data[0] << 8 | data[1]), 
                                    (unsigned short)(data[2] << 8 | data[3]), 
                                    (ares_dns_opcode_t)data[4], (ares_dns_rcode_t)data[5]);
    if (status != ARES_SUCCESS) {
        handle_error(dnsrec, &host);
        return 0;
    }

    // Parse the DNS response using the fuzzer input
    status = ares_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        handle_error(dnsrec, &host);
        return 0;
    }

    // Parse the PTR reply using the fuzzer input
    status = ares_parse_ptr_reply(data, size, data, size, AF_INET, &host);
    if (status != ARES_SUCCESS) {
        handle_error(dnsrec, &host);
        return 0;
    }

    // Cleanup resources
    handle_error(dnsrec, &host);
    return 0;
}
