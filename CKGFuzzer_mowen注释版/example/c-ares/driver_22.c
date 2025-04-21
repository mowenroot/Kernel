#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzzer input to a valid DNS opcode
ares_dns_opcode_t get_opcode(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Invalid opcode
    return (ares_dns_opcode_t)(data[0] % 16); // ARES_DNS_OPCODE_MAX is 16
}

// Function to convert fuzzer input to a valid DNS rcode
ares_dns_rcode_t get_rcode(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Invalid rcode
    return (ares_dns_rcode_t)(data[1] % 16); // ARES_DNS_RCODE_MAX is 16
}

// Function to convert fuzzer input to a valid DNS flags
unsigned short get_flags(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Invalid flags
    return (unsigned short)((data[2] << 8) | data[3]);
}

// Function to convert fuzzer input to a valid DNS ID
unsigned short get_id(const uint8_t *data, size_t size) {
    if (size < 6) return 0; // Invalid ID
    return (unsigned short)((data[4] << 8) | data[5]);
}

// Function to convert fuzzer input to a valid DNS section
ares_dns_section_t get_section(const uint8_t *data, size_t size) {
    if (size < 7) return 0; // Invalid section
    return (ares_dns_section_t)(data[6] % 3); // ARES_SECTION_MAX is 3
}

// Function to convert fuzzer input to a valid DNS record type
ares_dns_rec_type_t get_type(const uint8_t *data, size_t size) {
    if (size < 8) return 0; // Invalid type
    return (ares_dns_rec_type_t)(data[7] % 256); // ARES_DNS_REC_TYPE_MAX is 256
}

// Function to convert fuzzer input to a valid DNS class
ares_dns_class_t get_class(const uint8_t *data, size_t size) {
    if (size < 9) return 0; // Invalid class
    return (ares_dns_class_t)(data[8] % 256); // ARES_DNS_CLASS_MAX is 256
}

// Function to convert fuzzer input to a valid TTL
unsigned int get_ttl(const uint8_t *data, size_t size) {
    if (size < 13) return 0; // Invalid TTL
    return (unsigned int)((data[9] << 24) | (data[10] << 16) | (data[11] << 8) | data[12]);
}

// Function to extract a string from fuzzer input
const char *get_name(const uint8_t *data, size_t size, size_t *name_len) {
    if (size < 14) return NULL; // Invalid name
    *name_len = data[13];
    if (size < 14 + *name_len) return NULL; // Invalid name length
    return (const char *)&data[14];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_record_t *dnsrec_dup = NULL;
    ares_dns_rr_t *rr = NULL;
    ares_status_t status;
    size_t name_len;
    const char *name;

    // Extract parameters from fuzzer input
    ares_dns_opcode_t opcode = get_opcode(data, size);
    ares_dns_rcode_t rcode = get_rcode(data, size);
    unsigned short flags = get_flags(data, size);
    unsigned short id = get_id(data, size);
    ares_dns_section_t section = get_section(data, size);
    ares_dns_rec_type_t type = get_type(data, size);
    ares_dns_class_t rclass = get_class(data, size);
    unsigned int ttl = get_ttl(data, size);
    name = get_name(data, size, &name_len);

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Early exit on error
    }

    // Add a resource record to the DNS record
    if (name != NULL) {
        status = ares_dns_record_rr_add(&rr, dnsrec, section, name, type, rclass, ttl);
        if (status != ARES_SUCCESS) {
            ares_dns_record_destroy(dnsrec);
            return 0; // Early exit on error
        }
    }

    // Duplicate the DNS record
    dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup == NULL) {
        ares_dns_record_destroy(dnsrec);
        return 0; // Early exit on error
    }

    // Retrieve and validate flags and ID from the original and duplicated records
    unsigned short orig_flags = ares_dns_record_get_flags(dnsrec);
    unsigned short dup_flags = ares_dns_record_get_flags(dnsrec_dup);
    unsigned short orig_id = ares_dns_record_get_id(dnsrec);
    unsigned short dup_id = ares_dns_record_get_id(dnsrec_dup);

    if (orig_flags != dup_flags || orig_id != dup_id) {
        ares_dns_record_destroy(dnsrec);
        ares_dns_record_destroy(dnsrec_dup);
        return 0; // Early exit on validation failure
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    ares_dns_record_destroy(dnsrec_dup);

    return 0;
}
