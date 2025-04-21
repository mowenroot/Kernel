#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint16_t from the fuzz input
uint16_t extract_uint16(const uint8_t *data, size_t *offset, size_t max_input_size) {
    if (*offset + sizeof(uint16_t) > max_input_size) {
        return 0; // Return a default value if out of bounds
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += sizeof(uint16_t);
    return value;
}

// Function to safely extract a uint8_t from the fuzz input
uint8_t extract_uint8(const uint8_t *data, size_t *offset, size_t max_input_size) {
    if (*offset >= max_input_size) {
        return 0; // Return a default value if out of bounds
    }
    uint8_t value = data[*offset];
    *offset += sizeof(uint8_t);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const size_t MAX_INPUT_SIZE = 1024; // Limit input size to prevent excessive memory usage
    if (size > MAX_INPUT_SIZE) {
        return 0; // Ignore excessively large inputs
    }

    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;
    unsigned short id, flags;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;
    size_t offset = 0;

    // Extract values from fuzz input
    id = extract_uint16(data, &offset, MAX_INPUT_SIZE);
    flags = extract_uint16(data, &offset, MAX_INPUT_SIZE);
    opcode = (ares_dns_opcode_t)extract_uint8(data, &offset, MAX_INPUT_SIZE);
    rcode = (ares_dns_rcode_t)extract_uint8(data, &offset, MAX_INPUT_SIZE);

    // Create DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Handle error in creating DNS record
    }

    // Retrieve and use the flags, opcode, and rcode
    unsigned short retrieved_flags = ares_dns_record_get_flags(dnsrec);
    ares_dns_opcode_t retrieved_opcode = ares_dns_record_get_opcode(dnsrec);
    ares_dns_rcode_t retrieved_rcode = ares_dns_record_get_rcode(dnsrec);

    // Ensure retrieved values are valid (for debugging purposes)
    if (retrieved_flags != flags || retrieved_opcode != opcode || retrieved_rcode != rcode) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Handle inconsistency in retrieved values
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);
    return 0;
}
