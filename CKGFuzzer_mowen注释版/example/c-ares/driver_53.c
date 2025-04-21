#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely free a hostent structure
void safe_free_hostent(struct hostent *host) {
    if (host) {
        ares_free_hostent(host);
    }
}

// Function to safely free ares_soa_reply structure
void safe_free_soa_reply(struct ares_soa_reply *soa) {
    if (soa) {
        ares_free_data(soa);
    }
}

// Function to safely free ares_mx_reply linked list
void safe_free_mx_reply(struct ares_mx_reply *mx) {
    while (mx) {
        struct ares_mx_reply *next = mx->next;
        ares_free_data(mx);
        mx = next;
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract the length of the DNS response buffer
    int alen = *(int *)data;
    const unsigned char *abuf = data + sizeof(int);

    // Ensure the buffer is large enough to contain the DNS response
    if (size < sizeof(int) + (size_t)alen) {
        return 0;
    }

    // Variables to hold the results of the API calls
    struct hostent *host_a = NULL;
    struct hostent *host_aaaa = NULL;
    struct hostent *host_ns = NULL;
    struct ares_soa_reply *soa = NULL;
    struct ares_mx_reply *mx = NULL;

    // Buffers for TTLs
    struct ares_addrttl addrttls_a[1];
    struct ares_addr6ttl addrttls_aaaa[1];
    int naddrttls_a = 1;
    int naddrttls_aaaa = 1;

    // Call ares_parse_a_reply
    int status_a = ares_parse_a_reply(abuf, alen, &host_a, addrttls_a, &naddrttls_a);
    if (status_a != ARES_SUCCESS) {
        // Handle error
    }

    // Call ares_parse_aaaa_reply
    int status_aaaa = ares_parse_aaaa_reply(abuf, alen, &host_aaaa, addrttls_aaaa, &naddrttls_aaaa);
    if (status_aaaa != ARES_SUCCESS) {
        // Handle error
    }

    // Call ares_parse_ns_reply
    int status_ns = ares_parse_ns_reply(abuf, alen, &host_ns);
    if (status_ns != ARES_SUCCESS) {
        // Handle error
    }

    // Call ares_parse_soa_reply
    int status_soa = ares_parse_soa_reply(abuf, alen, &soa);
    if (status_soa != ARES_SUCCESS) {
        // Handle error
    }

    // Call ares_parse_mx_reply
    int status_mx = ares_parse_mx_reply(abuf, alen, &mx);
    if (status_mx != ARES_SUCCESS) {
        // Handle error
    }

    // Free allocated resources
    safe_free_hostent(host_a);
    safe_free_hostent(host_aaaa);
    safe_free_hostent(host_ns);
    safe_free_soa_reply(soa);
    safe_free_mx_reply(mx);

    return 0;
}
