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

// Function to safely convert fuzz input to an integer
static unsigned int safe_strntoul(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    char *endptr;
    char *str = safe_strndup(data, size);
    if (!str) return 0;
    unsigned long val = strtoul(str, &endptr, 10);
    free(str);
    return (unsigned int)val;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_rr_t *rr = NULL;
    ares_status_t status;

    // Ensure input size is sufficient for processing
    if (size < 10) return 0;

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, 
                                    (unsigned short)safe_strntoul(data, 2), 
                                    (unsigned short)safe_strntoul(data + 2, 2), 
                                    (ares_dns_opcode_t)safe_strntoul(data + 4, 1), 
                                    (ares_dns_rcode_t)safe_strntoul(data + 5, 1));
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Set query type
    status = ares_dns_record_query_set_type(dnsrec, 
                                            0, 
                                            (ares_dns_rec_type_t)safe_strntoul(data + 6, 2));
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Add a DNS resource record
    char *name = safe_strndup(data + 8, size - 8);
    if (!name) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    status = ares_dns_record_rr_add(&rr, 
                                    dnsrec, 
                                    ARES_SECTION_ANSWER, 
                                    name, 
                                    (ares_dns_rec_type_t)safe_strntoul(data + 6, 2), 
                                    (ares_dns_class_t)safe_strntoul(data + 6, 2), 
                                    3600);
    free(name);
    if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Retrieve and validate the address from the resource record
    const struct in_addr *addr = ares_dns_rr_get_addr(rr, 0);
    if (addr) {
        // Successfully retrieved address
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);
    return 0;
}
