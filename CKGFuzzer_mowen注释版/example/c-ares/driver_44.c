#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added to include the declaration of stderr

// Function to safely allocate memory
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy data
void safe_memcpy(void *dest, const void *src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safe_free(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is sufficient for processing
    if (size < sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t)) {
        return 0;
    }

    // Extract parameters from fuzz input
    unsigned short id = *(unsigned short *)data;
    unsigned short flags = *(unsigned short *)(data + sizeof(unsigned short));
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t *)(data + sizeof(unsigned short) * 2);
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t));

    // Create a DNS record
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Duplicate the DNS record
    ares_dns_record_t *dnsrec_dup = ares_dns_record_duplicate(dnsrec);
    if (dnsrec_dup) {
        ares_dns_record_destroy(dnsrec_dup);
    }

    // Expand name and string
    const unsigned char *encoded_name = (const unsigned char *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t));
    const unsigned char *encoded_string = encoded_name + 1; // Assume encoded_name is at least 1 byte long

    char *expanded_name = NULL;
    long name_len = 0;
    int expand_name_status = ares_expand_name(encoded_name, data, size, &expanded_name, &name_len);
    if (expand_name_status == ARES_SUCCESS) {
        ares_free_string(expanded_name);
    }

    unsigned char *expanded_string = NULL;
    long string_len = 0;
    int expand_string_status = ares_expand_string(encoded_string, data, size, &expanded_string, &string_len);
    if (expand_string_status == ARES_SUCCESS) {
        ares_free_string(expanded_string);
    }

    // Clean up
    ares_dns_record_destroy(dnsrec);

    return 0;
}
