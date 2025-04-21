#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t)) {
        return 0;
    }

    // Initialize variables
    ares_dns_rr_t* dns_rr = NULL;
    ares_dns_rr_key_t key;
    unsigned short opt;
    size_t val_len;
    const unsigned char* val = NULL;
    size_t opt_cnt;
    ares_status_t status;

    // Extract key, opt, and val_len from the fuzz input
    safe_memcpy(&key, data, sizeof(ares_dns_rr_key_t));
    safe_memcpy(&opt, data + sizeof(ares_dns_rr_key_t), sizeof(unsigned short));
    safe_memcpy(&val_len, data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short), sizeof(size_t));

    // Ensure val_len is within the remaining input size
    if (val_len > size - (sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t))) {
        val_len = size - (sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t));
    }

    // Allocate memory for dns_rr
    dns_rr = ares_dns_rr_create();  // Corrected to use the appropriate function

    // Set the option in the DNS resource record
    status = ares_dns_rr_set_opt(dns_rr, key, opt, data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t), val_len);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);  // Corrected to use the appropriate function
        return 0;
    }

    // Retrieve the option count
    opt_cnt = ares_dns_rr_get_opt_cnt(dns_rr, key);

    // Retrieve the option by ID
    ares_bool_t found = ares_dns_rr_get_opt_byid(dns_rr, key, opt, &val, &val_len);
    if (!found) {
        ares_dns_rr_destroy(dns_rr);  // Corrected to use the appropriate function
        return 0;
    }

    // Retrieve the option by index
    unsigned short retrieved_opt = ares_dns_rr_get_opt(dns_rr, key, 0, &val, &val_len);
    if (retrieved_opt == 65535) {
        ares_dns_rr_destroy(dns_rr);  // Corrected to use the appropriate function
        return 0;
    }

    // Free allocated resources
    ares_dns_rr_destroy(dns_rr);  // Corrected to use the appropriate function

    return 0;
}
