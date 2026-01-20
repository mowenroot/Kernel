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
static void* safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        // Handle out-of-memory condition
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
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize variables
    struct hostent *host_ptr = NULL;
    struct ares_addr6ttl *addr6ttls = NULL;
    int naddr6ttls = 0;
    struct ares_soa_reply *soa_reply = NULL;
    struct ares_addrttl *addrttls = NULL;
    int naddrttls = 0;
    ares_dns_record_t *dnsrec = NULL;
    int status;

    // Allocate memory for addr6ttls and addrttls
    addr6ttls = (struct ares_addr6ttl*)safe_malloc(sizeof(struct ares_addr6ttl));
    addrttls = (struct ares_addrttl*)safe_malloc(sizeof(struct ares_addrttl));

    // Call ares_dns_parse to parse the DNS response
    status = ares_dns_parse(data, size, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_parse_ptr_reply
    status = ares_parse_ptr_reply(data, size, NULL, 0, AF_INET, &host_ptr);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_parse_aaaa_reply
    status = ares_parse_aaaa_reply(data, size, &host_ptr, addr6ttls, &naddr6ttls);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_parse_soa_reply
    status = ares_parse_soa_reply(data, size, &soa_reply);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_parse_a_reply
    status = ares_parse_a_reply(data, size, &host_ptr, addrttls, &naddrttls);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

cleanup:
    // Free allocated resources
    ares_free_hostent(host_ptr);
    ares_free_data(soa_reply);
    ares_dns_record_destroy(dnsrec);
    safe_free(addr6ttls);
    safe_free(addrttls);

    return 0;
}
