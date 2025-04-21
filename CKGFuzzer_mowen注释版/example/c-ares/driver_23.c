#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr

// Function to safely allocate memory
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely duplicate a string
char *safe_strdup(const char *str) {
    if (!str) return NULL;
    char *dup = strdup(str);
    if (!dup) {
        fprintf(stderr, "String duplication failed\n");
        exit(EXIT_FAILURE);
    }
    return dup;
}

// Function to safely free memory
void safe_free(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(size_t) + sizeof(char) + sizeof(ares_dns_rec_type_t) + sizeof(ares_dns_class_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    ares_dns_rr_t *rr_out = NULL;

    ares_dns_section_t sect = (ares_dns_section_t)data[0];
    size_t idx = (size_t)data[1];
    char *name = (char *)safe_malloc(size - sizeof(ares_dns_section_t) - sizeof(size_t));
    memcpy(name, data + sizeof(ares_dns_section_t) + sizeof(size_t), size - sizeof(ares_dns_section_t) - sizeof(size_t));
    ares_dns_rec_type_t type = (ares_dns_rec_type_t)data[size - sizeof(ares_dns_rec_type_t) - sizeof(ares_dns_class_t) - sizeof(unsigned int)];
    ares_dns_class_t rclass = (ares_dns_class_t)data[size - sizeof(ares_dns_class_t) - sizeof(unsigned int)];
    unsigned int ttl = (unsigned int)data[size - sizeof(unsigned int)];

    // Add a DNS resource record
    ares_status_t status = ares_dns_record_rr_add(&rr_out, &dnsrec, sect, name, type, rclass, ttl);
    if (status != ARES_SUCCESS) {
        safe_free(name);
        return 0;
    }

    // Get the count of resource records
    size_t rr_cnt = ares_dns_record_rr_cnt(dnsrec, sect);

    // Get a specific resource record
    ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, sect, idx);
    if (rr) {
        // Get the address from the resource record
        ares_dns_rr_key_t key = (ares_dns_rr_key_t)data[2];
        const struct in_addr *addr = ares_dns_rr_get_addr(rr, key);
        if (addr) {
            // Use the address as needed
        }
    }

    // Delete a specific resource record
    status = ares_dns_record_rr_del(dnsrec, sect, idx);
    if (status != ARES_SUCCESS) {
        safe_free(name);
        return 0;
    }

    // Clean up
    ares_dns_record_free(dnsrec); // Free the DNS record structure
    safe_free(name);

    return 0;
}
