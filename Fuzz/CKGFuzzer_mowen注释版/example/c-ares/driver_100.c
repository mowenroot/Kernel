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

// Function to safely allocate memory for a structure
#define SAFE_ALLOC(type, count) ((type*)malloc(sizeof(type) * (count)))

// Function to safely free a linked list of structures
#define SAFE_FREE_LIST(head, type) \
    while (head) { \
        type *next = head->next; \
        free(head); \
        head = next; \
    }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int)) return 0;

    // Extract the length of the DNS response buffer
    int alen = *(int*)data;
    const unsigned char *abuf = data + sizeof(int);
    size_t abuf_size = size - sizeof(int);

    // Ensure the extracted length is within bounds
    if (alen < 0 || (size_t)alen > abuf_size) return 0;

    // Variables to hold the results of the API calls
    struct hostent *host = NULL;
    struct ares_addr6ttl *addr6ttls = NULL;
    int naddr6ttls = 0;
    struct ares_mx_reply *mx_reply = NULL;
    struct ares_soa_reply *soa_reply = NULL;
    struct ares_addrttl *addrttls = NULL;
    int naddrttls = 0;

    // Call ares_parse_aaaa_reply
    int status = ares_parse_aaaa_reply(abuf, alen, &host, addr6ttls, &naddr6ttls);
    if (status == ARES_SUCCESS) {
        // Free the hostent structure if allocated
        if (host) ares_free_hostent(host);
        // Free the addr6ttls if allocated
        if (addr6ttls) free(addr6ttls);
    }

    // Call ares_parse_ns_reply
    status = ares_parse_ns_reply(abuf, alen, &host);
    if (status == ARES_SUCCESS) {
        // Free the hostent structure if allocated
        if (host) ares_free_hostent(host);
    }

    // Call ares_parse_mx_reply
    status = ares_parse_mx_reply(abuf, alen, &mx_reply);
    if (status == ARES_SUCCESS) {
        // Free the mx_reply linked list if allocated
        if (mx_reply) ares_free_data(mx_reply);
    }

    // Call ares_parse_soa_reply
    status = ares_parse_soa_reply(abuf, alen, &soa_reply);
    if (status == ARES_SUCCESS) {
        // Free the soa_reply structure if allocated
        if (soa_reply) ares_free_data(soa_reply);
    }

    // Call ares_parse_ptr_reply
    status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
    if (status == ARES_SUCCESS) {
        // Free the hostent structure if allocated
        if (host) ares_free_hostent(host);
    }

    // Call ares_parse_a_reply
    status = ares_parse_a_reply(abuf, alen, &host, addrttls, &naddrttls);
    if (status == ARES_SUCCESS) {
        // Free the hostent structure if allocated
        if (host) ares_free_hostent(host);
        // Free the addrttls if allocated
        if (addrttls) free(addrttls);
    }

    return 0;
}
