#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert ares_dns_opcode_t to a valid opcode value
ares_dns_opcode_t get_valid_opcode(const uint8_t *data, size_t size) {
    if (size < 1) return ARES_OPCODE_QUERY; // Default to QUERY if no data
    return (ares_dns_opcode_t)(data[0] % 5); // Map to valid opcodes 0-4
}

// Function to convert ares_dns_rcode_t to a valid rcode value
ares_dns_rcode_t get_valid_rcode(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Default to 0 if no data
    return (ares_dns_rcode_t)(data[1] % 16); // Map to valid rcodes 0-15
}

// Function to get valid flags from the input data
unsigned short get_valid_flags(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Default to 0 if no data
    return (unsigned short)((data[2] << 8) | data[3]); // Combine two bytes to form flags
}

// Function to get a valid ID from the input data
unsigned short get_valid_id(const uint8_t *data, size_t size) {
    if (size < 6) return 0; // Default to 0 if no data
    return (unsigned short)((data[4] << 8) | data[5]); // Combine two bytes to form ID
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;
    unsigned short flags, id;

    // Initialize variables from fuzz input
    opcode = get_valid_opcode(data, size);
    rcode = get_valid_rcode(data, size);
    flags = get_valid_flags(data, size);
    id = get_valid_id(data, size);

    // Create DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        // Handle error, e.g., log or return early
        return 0;
    }

    // Retrieve and use rcode
    rcode = ares_dns_record_get_rcode(dnsrec);
    if (rcode != ares_dns_record_get_rcode(dnsrec)) {
        // Handle inconsistency, e.g., log or return early
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Retrieve and use flags
    flags = ares_dns_record_get_flags(dnsrec);
    if (flags != ares_dns_record_get_flags(dnsrec)) {
        // Handle inconsistency, e.g., log or return early
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Convert opcode to string
    const char *opcode_str = ares_dns_opcode_tostr(opcode);
    if (opcode_str == NULL) {
        // Handle error, e.g., log or return early
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    return 0;
}
