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

// Function to safely allocate memory for a buffer
static void* safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        // Handle allocation failure
        abort();
    }
    return ptr;
}

// Function to safely free memory
static void safe_free(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is reasonable
    if (size < 1 || size > 1024) {
        return 0;
    }

    // Variables for API calls
    struct hostent *host = NULL;
    struct ares_addr6ttl addr6ttls[1];
    struct ares_addrttl addrttls[1];
    int naddrttls = 1;
    unsigned char *query_buf = NULL;
    int query_len = 0;
    char *hostname = safe_strndup(data, size);
    if (!hostname) {
        return 0;
    }

    // Create a DNS query
    int status = ares_mkquery(hostname, C_IN, T_A, 1, 1, &query_buf, &query_len);
    if (status != ARES_SUCCESS) {
        safe_free(hostname);
        return 0;
    }

    // Parse AAAA reply
    status = ares_parse_aaaa_reply(query_buf, query_len, &host, addr6ttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        safe_free(hostname);
        safe_free(query_buf);
        return 0;
    }

    // Parse A reply
    status = ares_parse_a_reply(query_buf, query_len, &host, addrttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        safe_free(hostname);
        safe_free(query_buf);
        return 0;
    }

    // Parse PTR reply
    status = ares_parse_ptr_reply(query_buf, query_len, NULL, 0, AF_INET, &host);
    if (status != ARES_SUCCESS) {
        safe_free(hostname);
        safe_free(query_buf);
        return 0;
    }

    // Convert IP address to binary form
    struct in_addr ipv4;
    status = ares_inet_pton(AF_INET, hostname, &ipv4);
    if (status != 1) {
        safe_free(hostname);
        safe_free(query_buf);
        return 0;
    }

    // Clean up
    safe_free(hostname);
    safe_free(query_buf);
    return 0;
}
