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

// Function to safely convert fuzz input to a valid DNS section
static ares_dns_section_t safe_dns_section(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return (ares_dns_section_t)(data[0] % 3); // Assuming DNS section is within 0-2
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_rr_t *rr = NULL;
    ares_status_t status;
    size_t query_cnt;
    const char *query_name = NULL;
    ares_dns_rec_type_t query_type;
    ares_dns_class_t query_class;

    // Allocate memory for DNS record
    status = ares_dns_record_create(&dnsrec, 0, 0, 0, 0); // Correct function to create the DNS record
    if (status != ARES_SUCCESS) return 0;

    // Set DNS record query type
    status = ares_dns_record_query_set_type(dnsrec, 0, safe_dns_rec_type(data, size));
    if (status != ARES_SUCCESS) goto cleanup;

    // Set DNS record query name
    char *name = safe_strndup(data, size);
    if (!name) goto cleanup;
    status = ares_dns_record_query_set_name(dnsrec, 0, name);
    free(name);
    if (status != ARES_SUCCESS) goto cleanup;

    // Add DNS resource record
    status = ares_dns_record_rr_add(&rr, dnsrec, safe_dns_section(data, size), "example.com", safe_dns_rec_type(data, size), safe_dns_class(data, size), 3600);
    if (status != ARES_SUCCESS) goto cleanup;

    // Get DNS record query details
    status = ares_dns_record_query_get(dnsrec, 0, &query_name, &query_type, &query_class);
    if (status != ARES_SUCCESS) goto cleanup;

    // Cleanup
cleanup:
    if (dnsrec) {
        // Free any allocated resources within dnsrec
        ares_dns_record_destroy(dnsrec); // Correct function to free the DNS record
    }
    if (rr) {
        // Free any allocated resources within rr
        ares_dns_rr_destroy(rr); // Correct function to free the DNS resource record
    }

    return 0;
}
