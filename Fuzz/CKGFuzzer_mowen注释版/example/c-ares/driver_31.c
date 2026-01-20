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

// Function to safely allocate memory for ares_dns_rr_t
static ares_dns_rr_t* safe_dns_rr_alloc(size_t size) {
    // Instead of directly allocating memory, use the library's function to create a DNS resource record
    ares_dns_rr_t *dns_rr = NULL;
    ares_status_t status = ares_dns_rr_create(&dns_rr, (unsigned int)size);
    if (status != ARES_SUCCESS) return NULL;
    return dns_rr;
}

// Function to safely allocate memory for ares_channel_t
static ares_channel_t* safe_channel_alloc(size_t size) {
    // Instead of directly allocating memory, use the library's function to initialize a channel
    ares_channel_t *channel = NULL;
    if (ares_init(&channel) != ARES_SUCCESS) return NULL;
    return channel;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Minimum input size required

    // Initialize variables
    ares_dns_rr_t *dns_rr = NULL;
    ares_channel_t *channel = NULL;
    char *name = NULL;
    ares_dns_rr_key_t key = (ares_dns_rr_key_t)data[0]; // Use first byte as key

    // Allocate memory for DNS resource record and channel
    dns_rr = safe_dns_rr_alloc(size);
    channel = safe_channel_alloc(size);
    if (!dns_rr || !channel) goto cleanup;

    // Safely copy the name from fuzz input
    name = safe_strndup(data + 1, size - 1);
    if (!name) goto cleanup;

    // Call APIs with robust error handling
    const struct ares_in6_addr *addr6 = ares_dns_rr_get_addr6(dns_rr, key);
    if (addr6) {
        // Handle addr6 if not NULL
    }

    const struct in_addr *addr = ares_dns_rr_get_addr(dns_rr, key);
    if (addr) {
        // Handle addr if not NULL
    }

    unsigned int ttl = ares_dns_rr_get_ttl(dns_rr);
    if (ttl) {
        // Handle ttl if not 0
    }

    unsigned char u8 = ares_dns_rr_get_u8(dns_rr, key);
    if (u8) {
        // Handle u8 if not 0
    }

    // Perform a DNS search with the provided name
    ares_search(channel, name, C_IN, T_A, NULL, NULL);

cleanup:
    // Free allocated resources
    if (dns_rr) ares_dns_rr_destroy(dns_rr);
    if (channel) ares_destroy(channel);
    free(name);

    return 0;
}
