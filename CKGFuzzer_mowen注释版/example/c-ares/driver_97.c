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
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Extract parameters from fuzz input
    uint16_t id = extract_uint16(data, &offset);
    uint16_t flags = extract_uint16(data, &offset);
    uint8_t opcode = extract_uint8(data, &offset);
    uint8_t rcode = extract_uint8(data, &offset);

    // Create DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Failed to create DNS record
    }

    // Extract more parameters for option handling
    uint16_t opt = extract_uint16(data, &offset);
    uint8_t key = extract_uint8(data, &offset);

    // Get data type and name for the option
    ares_dns_opt_datatype_t datatype = ares_dns_opt_get_datatype(key, opt);
    const char *opt_name = ares_dns_opt_get_name(key, opt);

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Failed to duplicate DNS record
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    ares_dns_record_destroy(dnsrec_dup);

    return 0;
}
