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

// Function to safely allocate memory for ares_dns_record_t
static ares_dns_record_t* safe_dns_record_create(const uint8_t *data, size_t size) {
    if (size < 6) return NULL; // Need at least 6 bytes for id, flags, opcode, rcode

    unsigned short id = (data[0] << 8) | data[1];
    unsigned short flags = (data[2] << 8) | data[3];
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];

    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return NULL;
    }
    return dnsrec;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 6) return 0;

    // Create a DNS record from fuzz input
    ares_dns_record_t *dnsrec = safe_dns_record_create(data, size);
    if (!dnsrec) return 0;

    // Retrieve and print flags from the DNS record
    unsigned short flags = ares_dns_record_get_flags(dnsrec);
    (void)flags; // Suppress unused variable warning

    // Parse a PTR reply using the DNS record
    struct hostent *host = NULL;
    int status = ares_parse_ptr_reply((const unsigned char*)data, size, NULL, 0, AF_INET, &host);
    if (status != ARES_SUCCESS) {
        // Handle error
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Clean up resources
    if (host) free(host);
    ares_dns_record_destroy(dnsrec);

    return 0;
}
