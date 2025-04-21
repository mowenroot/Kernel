#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely extract a short value from fuzz input
static unsigned short safe_extract_short(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(unsigned short) > size) {
        return 0;
    }
    unsigned short value = *(unsigned short*)(data + *offset);
    *offset += sizeof(unsigned short);
    return value;
}

// Function to safely extract a size_t value from fuzz input
static size_t safe_extract_size_t(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(size_t) > size) {
        return 0;
    }
    size_t value = *(size_t*)(data + *offset);
    *offset += sizeof(size_t);
    return value;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;
    size_t offset = 0;

    // Extract parameters from fuzz input
    unsigned short id = safe_extract_short(data, size, &offset);
    unsigned short flags = safe_extract_short(data, size, &offset);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)safe_extract_short(data, size, &offset);
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)safe_extract_short(data, size, &offset);
    size_t idx = safe_extract_size_t(data, size, &offset);
    char *name = safe_strndup(data + offset, size - offset);

    // Create DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        free(name);
        return 0;
    }

    // Set query name
    status = ares_dns_record_query_set_name(dnsrec, idx, name);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        free(name);
        return 0;
    }

    // Get flags
    unsigned short retrieved_flags = ares_dns_record_get_flags(dnsrec);

    // Get resource record
    ares_dns_section_t sect = ARES_SECTION_ANSWER; // Example section
    ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, sect, idx);

    // Clean up
    ares_dns_record_destroy(dnsrec);
    free(name);

    return 0;
}
