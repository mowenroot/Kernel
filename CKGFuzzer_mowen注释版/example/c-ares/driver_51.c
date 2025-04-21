#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added this include to resolve the 'stderr' undeclared identifier error

// Function to safely copy a string with bounds checking
static void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

// Function to safely allocate memory and handle errors
static void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely reallocate memory and handle errors
static void *safe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t) + 1) {
        return 0;
    }

    // Initialize variables
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    struct hostent *host = NULL;
    struct ares_addrttl *addrttls = NULL;
    int naddrttls = 0;
    int status;

    // Extract data for API inputs
    unsigned short id = *(unsigned short *)data;
    unsigned short flags = *(unsigned short *)(data + sizeof(unsigned short));
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t *)(data + sizeof(unsigned short) * 2);
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t));
    const char *local_dev_name = (const char *)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t));

    // Create a DNS record
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Initialize the ares library
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Set the local device name
    ares_set_local_dev(channel, local_dev_name);

    // Parse the DNS reply
    status = ares_parse_a_reply((const unsigned char *)data, size, &host, addrttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Perform a hostname lookup
    ares_gethostbyname(channel, "example.com", AF_INET, NULL, NULL);

cleanup:
    // Free allocated resources
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
    if (host) {
        ares_free_hostent(host);
    }
    if (addrttls) {
        free(addrttls);
    }
    ares_library_cleanup();

    return 0;
}
