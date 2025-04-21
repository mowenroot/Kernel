#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint16_t from the fuzz input
uint16_t safe_extract_uint16(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + 2 > size) {
        return 0; // Return 0 if not enough data
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += 2;
    return value;
}

// Function to safely extract a uint8_t from the fuzz input
uint8_t safe_extract_uint8(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset >= size) {
        return 0; // Return 0 if not enough data
    }
    return data[(*offset)++];
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Extract parameters from fuzz input
    uint16_t id = safe_extract_uint16(data, size, &offset);
    uint16_t flags = safe_extract_uint16(data, size, &offset);
    uint8_t opcode = safe_extract_uint8(data, size, &offset);
    uint8_t rcode = safe_extract_uint8(data, size, &offset);

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Early exit if creation fails
    }

    // Parse DNS response data
    status = ares_dns_parse(data + offset, size - offset, 0, &dnsrec_dup);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Early exit if parsing fails
    }

    // Duplicate the DNS record
    ares_dns_record_t *dnsrec_dup2 = ares_dns_record_duplicate(dnsrec_dup);
    if (dnsrec_dup2) {
        ares_dns_record_destroy(dnsrec_dup2);
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    ares_dns_record_destroy(dnsrec_dup);

    return 0;
}
