#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    size_t len = strnlen((const char*)data, size);
    char *str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely convert fuzz input to an integer
static int safe_atoi(const uint8_t *data, size_t size) {
    char buf[12]; // Max length for an int is 11 characters (+1 for null terminator)
    size_t len = size < 11 ? size : 11;
    memcpy(buf, data, len);
    buf[len] = '\0';
    return atoi(buf);
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_rr_t *rr = NULL;
    ares_status_t status;
    char *name = NULL;
    int ttl;

    // Ensure we have enough input data
    if (size < 10) {
        return 0;
    }

    // Allocate and initialize a DNS record
    status = ares_dns_record_create(&dnsrec, 1, 1, 1, 1); // Added missing argument
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Set query name
    name = safe_strndup(data, size / 2);
    if (!name) {
        status = ARES_ENOMEM;
        goto cleanup;
    }
    status = ares_dns_record_query_set_name(dnsrec, 0, name);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Set query type
    ares_dns_rec_type_t qtype = (ares_dns_rec_type_t)(data[size / 2] % 256); // Arbitrary type selection
    status = ares_dns_record_query_set_type(dnsrec, 0, qtype);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Add a DNS query
    status = ares_dns_record_query_add(dnsrec, name, qtype, ARES_CLASS_IN); // Corrected to ARES_CLASS_IN
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Add a DNS resource record
    ttl = safe_atoi(data + size / 2 + 1, size / 2 - 1);
    status = ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, name, qtype, ARES_CLASS_IN, ttl); // Corrected to ARES_CLASS_IN
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Parse PTR reply (simulated)
    unsigned char abuf[1024]; // Simulated buffer
    int alen = 1024;
    struct hostent *host = NULL;
    status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

cleanup:
    // Free allocated resources
    ares_dns_record_destroy(dnsrec);
    free(name);
    if (host) {
        ares_free_hostent(host);
    }

    return 0;
}
