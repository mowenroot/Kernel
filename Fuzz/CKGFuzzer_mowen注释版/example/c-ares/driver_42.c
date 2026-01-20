#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint16_t from the fuzz input
uint16_t extract_uint16(const uint8_t *data, size_t *offset) {
    if (*offset + 2 > SIZE_MAX) {
        return 0; // Prevent overflow
    }
    uint16_t value = (uint16_t)data[*offset] | ((uint16_t)data[*offset + 1] << 8);
    *offset += 2;
    return value;
}

// Function to safely extract a uint8_t from the fuzz input
uint8_t extract_uint8(const uint8_t *data, size_t *offset) {
    if (*offset >= SIZE_MAX) {
        return 0; // Prevent overflow
    }
    uint8_t value = data[*offset];
    *offset += 1;
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0; // Insufficient data to proceed
    }

    size_t offset = 0;

    // Extract parameters from fuzz input
    unsigned short id = extract_uint16(data, &offset);
    unsigned short flags = extract_uint16(data, &offset);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)extract_uint8(data, &offset);
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)extract_uint8(data, &offset);

    // Create a DNS record
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Failed to create DNS record
    }

    // Retrieve and use the opcode
    ares_dns_opcode_t retrieved_opcode = ares_dns_record_get_opcode(dnsrec);
    (void)retrieved_opcode; // Suppress unused variable warning

    // Retrieve and use the flags
    unsigned short retrieved_flags = ares_dns_record_get_flags(dnsrec);
    (void)retrieved_flags; // Suppress unused variable warning

    // Convert DNS class to string (for demonstration purposes)
    ares_dns_class_t qclass = (ares_dns_class_t)extract_uint8(data, &offset);
    const char *class_str = ares_dns_class_tostr(qclass);
    (void)class_str; // Suppress unused variable warning

    // Clean up resources
    ares_dns_record_destroy(dnsrec);

    return 0;
}
