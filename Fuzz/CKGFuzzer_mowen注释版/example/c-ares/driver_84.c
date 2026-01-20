#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(unsigned char *dest, const uint8_t *src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data
unsigned char* safe_alloc_copy(const uint8_t *data, size_t size) {
    unsigned char *temp = (unsigned char *)malloc(size);
    if (temp) {
        safe_copy(temp, data, size);
    }
    return temp;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is sufficient for basic operations
    if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t)) {
        return 0;
    }

    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_dns_rr_key_t key;
    unsigned short opt;
    size_t val_len;
    unsigned char *val = NULL;
    ares_status_t status;

    // Extract key, opt, and val_len from fuzz input
    memcpy(&key, data, sizeof(ares_dns_rr_key_t));
    memcpy(&opt, data + sizeof(ares_dns_rr_key_t), sizeof(unsigned short));
    memcpy(&val_len, data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short), sizeof(size_t));

    // Ensure val_len is within bounds
    if (val_len > size - (sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t))) {
        return 0;
    }

    // Allocate and copy val from fuzz input
    val = safe_alloc_copy(data + sizeof(ares_dns_rr_key_t) + sizeof(unsigned short) + sizeof(size_t), val_len);
    if (!val) {
        return 0;
    }

    // Create a DNS resource record
    dns_rr = ares_dns_rr_create();
    if (!dns_rr) {
        free(val);
        return 0;
    }

    // Set an option in the DNS resource record
    status = ares_dns_rr_set_opt(dns_rr, key, opt, val, val_len);
    if (status != ARES_SUCCESS) {
        ares_dns_rr_destroy(dns_rr);
        free(val);
        return 0;
    }

    // Retrieve and validate the option by ID
    const unsigned char *retrieved_val = NULL;
    size_t retrieved_val_len = 0;
    ares_bool_t found = ares_dns_rr_get_opt_byid(dns_rr, key, opt, &retrieved_val, &retrieved_val_len);
    if (!found || retrieved_val_len != val_len || memcmp(retrieved_val, val, val_len) != 0) {
        ares_dns_rr_destroy(dns_rr);
        free(val);
        return 0;
    }

    // Retrieve and validate the option by index
    unsigned short retrieved_opt = ares_dns_rr_get_opt(dns_rr, key, 0, &retrieved_val, &retrieved_val_len);
    if (retrieved_opt != opt || retrieved_val_len != val_len || memcmp(retrieved_val, val, val_len) != 0) {
        ares_dns_rr_destroy(dns_rr);
        free(val);
        return 0;
    }

    // Retrieve the count of options
    size_t opt_cnt = ares_dns_rr_get_opt_cnt(dns_rr, key);
    if (opt_cnt != 1) {
        ares_dns_rr_destroy(dns_rr);
        free(val);
        return 0;
    }

    // Retrieve and validate the IPv4 address
    const struct in_addr *addr = ares_dns_rr_get_addr(dns_rr, key);
    if (addr) {
        // Additional validation can be added here if needed
    }

    // Retrieve and validate the IPv6 address
    const struct ares_in6_addr *addr6 = ares_dns_rr_get_addr6(dns_rr, key);
    if (addr6) {
        // Additional validation can be added here if needed
    }

    // Clean up
    ares_dns_rr_destroy(dns_rr);
    free(val);

    return 0;
}
