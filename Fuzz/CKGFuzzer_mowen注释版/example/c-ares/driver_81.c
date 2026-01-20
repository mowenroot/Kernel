#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char *)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a valid DNS record type
static ares_dns_rec_type_t safe_dns_rec_type(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (ares_dns_rec_type_t)(data[0] % 256); // Assuming DNS record type is within 0-255
}

// Function to safely convert fuzz input to a valid DNS class
static ares_dns_class_t safe_dns_class(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (ares_dns_class_t)(data[0] % 256); // Assuming DNS class is within 0-255
}

// Function to safely convert fuzz input to a valid DNS opcode
static ares_dns_opcode_t safe_dns_opcode(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (ares_dns_opcode_t)(data[0] % 256); // Assuming DNS opcode is within 0-255
}

// Function to safely convert fuzz input to a valid DNS rcode
static ares_dns_rcode_t safe_dns_rcode(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (ares_dns_rcode_t)(data[0] % 256); // Assuming DNS rcode is within 0-255
}

// Function to safely convert fuzz input to a valid DNS flags
static unsigned short safe_dns_flags(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (unsigned short)(data[0] % 256); // Assuming DNS flags are within 0-255
}

// Function to safely convert fuzz input to a valid DNS ID
static unsigned short safe_dns_id(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (unsigned short)(data[0] % 256); // Assuming DNS ID is within 0-255
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;
    size_t query_count;
    const char *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t qclass;

    // Ensure we have enough data for basic operations
    if (size < 8) return 0;

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec,
                                    safe_dns_id(data, 1),
                                    safe_dns_flags(data + 1, 1),
                                    safe_dns_opcode(data + 2, 1),
                                    safe_dns_rcode(data + 3, 1));
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Add a DNS query
    status = ares_dns_record_query_add(dnsrec,
                                       safe_strndup(data + 4, size - 4),
                                       safe_dns_rec_type(data + 4, 1),
                                       safe_dns_class(data + 5, 1));
    if (status != ARES_SUCCESS) {
        ares_dns_record_free(dnsrec);
        return 0;
    }

    // Set the query type
    status = ares_dns_record_query_set_type(dnsrec, 0, safe_dns_rec_type(data + 6, 1));
    if (status != ARES_SUCCESS) {
        ares_dns_record_free(dnsrec);
        return 0;
    }

    // Set the query name
    status = ares_dns_record_query_set_name(dnsrec, 0, safe_strndup(data + 7, size - 7));
    if (status != ARES_SUCCESS) {
        ares_dns_record_free(dnsrec);
        return 0;
    }

    // Get the query count
    query_count = ares_dns_record_query_cnt(dnsrec);

    // Get the query details
    status = ares_dns_record_query_get(dnsrec, 0, &name, &qtype, &qclass);
    if (status != ARES_SUCCESS) {
        ares_dns_record_free(dnsrec);
        return 0;
    }

    // Free the DNS record
    ares_dns_record_free(dnsrec);

    return 0;
}
