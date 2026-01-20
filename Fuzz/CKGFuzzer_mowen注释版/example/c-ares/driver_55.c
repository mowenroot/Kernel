#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to extract a specific number of bytes from the fuzz input
static int extract_bytes(const uint8_t *data, size_t size, size_t offset, size_t num_bytes, uint8_t *out) {
    if (offset + num_bytes > size) {
        return 0; // Not enough data
    }
    memcpy(out, data + offset, num_bytes);
    return 1;
}

// Function to extract a 16-bit unsigned integer from the fuzz input
static int extract_u16(const uint8_t *data, size_t size, size_t offset, uint16_t *out) {
    uint8_t bytes[2];
    if (!extract_bytes(data, size, offset, 2, bytes)) {
        return 0; // Not enough data
    }
    *out = (uint16_t)((bytes[0] << 8) | bytes[1]);
    return 1;
}

// Function to extract a 8-bit unsigned integer from the fuzz input
static int extract_u8(const uint8_t *data, size_t size, size_t offset, uint8_t *out) {
    if (offset >= size) {
        return 0; // Not enough data
    }
    *out = data[offset];
    return 1;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    struct ares_naptr_reply *naptr_reply = NULL;
    struct ares_caa_reply *caa_reply = NULL;
    struct ares_txt_reply *txt_reply = NULL;
    uint16_t id, flags;
    uint8_t opcode, rcode;
    int status;

    // Ensure we have enough data to extract the required fields
    if (size < 6) {
        return 0; // Not enough data
    }

    // Extract DNS record parameters from fuzz input
    if (!extract_u16(data, size, 0, &id) ||
        !extract_u16(data, size, 2, &flags) ||
        !extract_u8(data, size, 4, &opcode) ||
        !extract_u8(data, size, 5, &rcode)) {
        return 0; // Not enough data
    }

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, (ares_dns_opcode_t)opcode, (ares_dns_rcode_t)rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Failed to create DNS record
    }

    // Parse NAPTR reply
    status = ares_parse_naptr_reply(data, size, &naptr_reply);
    if (status != ARES_SUCCESS && status != ARES_ENODATA) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Failed to parse NAPTR reply
    }

    // Parse CAA reply
    status = ares_parse_caa_reply(data, size, &caa_reply);
    if (status != ARES_SUCCESS && status != ARES_ENODATA) {
        ares_free_data(naptr_reply);
        ares_dns_record_destroy(dnsrec);
        return 0; // Failed to parse CAA reply
    }

    // Parse TXT reply
    status = ares_parse_txt_reply(data, size, &txt_reply);
    if (status != ARES_SUCCESS && status != ARES_ENODATA) {
        ares_free_data(naptr_reply);
        ares_free_data(caa_reply);
        ares_dns_record_destroy(dnsrec);
        return 0; // Failed to parse TXT reply
    }

    // Clean up
    ares_free_data(naptr_reply);
    ares_free_data(caa_reply);
    ares_free_data(txt_reply);
    ares_dns_record_destroy(dnsrec);

    return 0;
}
