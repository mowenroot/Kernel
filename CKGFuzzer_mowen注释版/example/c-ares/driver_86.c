#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static const char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char *)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely extract a short value from fuzz input
static unsigned short safe_get_short(const uint8_t *data, size_t *offset) {
    if (*offset + sizeof(unsigned short) > SIZE_MAX) return 0;
    unsigned short value = *(unsigned short *)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract a string from fuzz input
static const char* safe_get_string(const uint8_t *data, size_t *offset, size_t size) {
    if (*offset >= size) return NULL;
    const char *str = (const char *)data + *offset;
    *offset += strlen(str) + 1;
    return str;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned short) * 3) return 0; // Need at least 3 shorts for id, flags, and opcode

    size_t offset = 0;

    // Extract id, flags, and opcode from fuzz input
    unsigned short id = safe_get_short(data, &offset);
    unsigned short flags = safe_get_short(data, &offset);
    unsigned short opcode_value = safe_get_short(data, &offset);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)opcode_value;
    ares_dns_rcode_t rcode = ARES_RCODE_NOERROR; // Default rcode

    // Create a DNS record
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0; // Failed to create DNS record
    }

    // Get flags from the DNS record
    unsigned short retrieved_flags = ares_dns_record_get_flags(dnsrec);

    // Duplicate the DNS record
    ares_dns_record_t *dup_dnsrec = ares_dns_record_duplicate(dnsrec);
    if (dup_dnsrec) {
        // Destroy the duplicate record
        ares_dns_record_destroy(dup_dnsrec);
    }

    // Extract a string for DNS class from fuzz input
    const char *class_str = safe_get_string(data, &offset, size);
    if (class_str) {
        ares_dns_class_t qclass;
        if (ares_dns_class_fromstr(&qclass, class_str)) {
            // Successfully converted string to DNS class
        }
        free((void *)class_str);
    }

    // Destroy the original DNS record
    ares_dns_record_destroy(dnsrec);

    return 0;
}
