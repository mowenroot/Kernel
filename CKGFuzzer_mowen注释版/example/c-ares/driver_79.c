#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to extract a valid opcode from the fuzz input
ares_dns_opcode_t get_opcode_from_input(const uint8_t *data, size_t size) {
    if (size < sizeof(ares_dns_opcode_t)) {
        return 0; // Invalid opcode
    }
    return (ares_dns_opcode_t)data[0];
}

// Function to extract a valid rcode from the fuzz input
ares_dns_rcode_t get_rcode_from_input(const uint8_t *data, size_t size) {
    if (size < sizeof(ares_dns_rcode_t)) {
        return 0; // Invalid rcode
    }
    return (ares_dns_rcode_t)data[1];
}

// Function to extract valid flags from the fuzz input
unsigned short get_flags_from_input(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned short)) {
        return 0; // Invalid flags
    }
    return (unsigned short)((data[2] << 8) | data[3]);
}

// Function to extract a valid ID from the fuzz input
unsigned short get_id_from_input(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned short)) {
        return 0; // Invalid ID
    }
    return (unsigned short)((data[4] << 8) | data[5]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract all necessary fields
    if (size < 6) {
        return 0; // Not enough data to proceed
    }

    // Extract necessary fields from the fuzz input
    ares_dns_opcode_t opcode = get_opcode_from_input(data, size);
    ares_dns_rcode_t rcode = get_rcode_from_input(data, size);
    unsigned short flags = get_flags_from_input(data, size);
    unsigned short id = get_id_from_input(data, size);

    // Create a DNS record using the extracted fields
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Failed to create DNS record
    }

    // Duplicate the DNS record
    ares_dns_record_t *dup_dnsrec = ares_dns_record_duplicate(dnsrec);
    if (dup_dnsrec == NULL) {
        ares_free(dnsrec);
        return 0; // Failed to duplicate DNS record
    }

    // Retrieve and validate the opcode from the original and duplicated records
    ares_dns_opcode_t orig_opcode = ares_dns_record_get_opcode(dnsrec);
    ares_dns_opcode_t dup_opcode = ares_dns_record_get_opcode(dup_dnsrec);
    if (orig_opcode != dup_opcode) {
        ares_free(dnsrec);
        ares_free(dup_dnsrec);
        return 0; // Opcode mismatch
    }

    // Retrieve and validate the rcode from the original and duplicated records
    ares_dns_rcode_t orig_rcode = ares_dns_record_get_rcode(dnsrec);
    ares_dns_rcode_t dup_rcode = ares_dns_record_get_rcode(dup_dnsrec);
    if (orig_rcode != dup_rcode) {
        ares_free(dnsrec);
        ares_free(dup_dnsrec);
        return 0; // Rcode mismatch
    }

    // Retrieve and validate the flags from the original and duplicated records
    unsigned short orig_flags = ares_dns_record_get_flags(dnsrec);
    unsigned short dup_flags = ares_dns_record_get_flags(dup_dnsrec);
    if (orig_flags != dup_flags) {
        ares_free(dnsrec);
        ares_free(dup_dnsrec);
        return 0; // Flags mismatch
    }

    // Clean up allocated resources
    ares_free(dnsrec);
    ares_free(dup_dnsrec);

    return 0;
}
