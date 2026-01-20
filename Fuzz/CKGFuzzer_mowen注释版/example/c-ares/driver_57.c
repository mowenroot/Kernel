#include <stdio.h>  // Include this header to declare stderr
#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely duplicate a string
char* safe_strdup(const char* str) {
    if (!str) return NULL;
    char* new_str = strdup(str);
    if (!new_str) {
        fprintf(stderr, "String duplication failed\n");
        exit(EXIT_FAILURE);
    }
    return new_str;
}

// Function to safely free a string
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely free a hostent structure
void safe_free_hostent(struct hostent* host) {
    if (host) {
        ares_free_hostent(host);
    }
}

// Function to safely free ares_srv_reply structure
void safe_free_srv_reply(struct ares_srv_reply* srv) {
    if (srv) {
        ares_free_data(srv);
    }
}

// Function to safely free ares_soa_reply structure
void safe_free_soa_reply(struct ares_soa_reply* soa) {
    if (soa) {
        ares_free_data(soa);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract the length of the DNS response buffer
    int alen = *(int*)data;
    if (alen < 0 || (size_t)alen > size - sizeof(int)) {
        return 0;
    }

    // Extract the DNS response buffer
    const unsigned char* abuf = (const unsigned char*)(data + sizeof(int));

    // Variables for API calls
    struct hostent* host = NULL;
    struct ares_addr6ttl* addr6ttls = NULL;
    struct ares_addrttl* addrttls = NULL;
    struct ares_srv_reply* srv_reply = NULL;
    struct ares_soa_reply* soa_reply = NULL;
    int naddrttls = 0;
    int status;

    // Call ares_parse_aaaa_reply
    status = ares_parse_aaaa_reply(abuf, alen, &host, addr6ttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_aaaa_reply failed with status: %d\n", status);
    }
    safe_free_hostent(host);

    // Call ares_parse_ns_reply
    status = ares_parse_ns_reply(abuf, alen, &host);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_ns_reply failed with status: %d\n", status);
    }
    safe_free_hostent(host);

    // Call ares_parse_srv_reply
    status = ares_parse_srv_reply(abuf, alen, &srv_reply);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_srv_reply failed with status: %d\n", status);
    }
    safe_free_srv_reply(srv_reply);

    // Call ares_parse_soa_reply
    status = ares_parse_soa_reply(abuf, alen, &soa_reply);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_soa_reply failed with status: %d\n", status);
    }
    safe_free_soa_reply(soa_reply);

    // Call ares_parse_ptr_reply
    status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_ptr_reply failed with status: %d\n", status);
    }
    safe_free_hostent(host);

    // Call ares_parse_a_reply
    status = ares_parse_a_reply(abuf, alen, &host, addrttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "ares_parse_a_reply failed with status: %d\n", status);
    }
    safe_free_hostent(host);

    return 0;
}
