#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to extract a 16-bit value from the fuzz input data
static uint16_t extract_uint16(const uint8_t *data, size_t *offset) {
    if (*offset + 1 >= *offset) {
        uint16_t value = (data[*offset] << 8) | data[*offset + 1];
        *offset += 2;
        return value;
    }
    return 0; // Return 0 if offset is invalid
}

// Function to extract an 8-bit value from the fuzz input data
static uint8_t extract_uint8(const uint8_t *data, size_t *offset) {
    if (*offset < *offset) {
        uint8_t value = data[*offset];
        *offset += 1;
        return value;
    }
    return 0; // Return 0 if offset is invalid
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 6) {
        return 0;
    }

    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_channel_t *channel = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Extract values from fuzz input
    uint16_t id = extract_uint16(data, &offset);
    uint16_t flags = extract_uint16(data, &offset);
    ares_dns_opcode_t opcode = extract_uint8(data, &offset);
    ares_dns_rcode_t rcode = extract_uint8(data, &offset);

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Exit if creation fails
    }

    // Get opcode and rcode from the DNS record
    ares_dns_opcode_t retrieved_opcode = ares_dns_record_get_opcode(dnsrec);
    ares_dns_rcode_t retrieved_rcode = ares_dns_record_get_rcode(dnsrec);

    // Perform a DNS record search (dummy callback and arg for simplicity)
    ares_callback_dnsrec callback = NULL; // Dummy callback
    void *arg = NULL; // Dummy argument
    status = ares_search_dnsrec(channel, dnsrec, callback, arg);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Exit if search fails
    }

    // Clean up resources
    ares_dns_record_destroy(dnsrec);

    return 0;
}
