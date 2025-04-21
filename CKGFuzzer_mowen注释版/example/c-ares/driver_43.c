#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include stdio.h for stderr

// Function to safely allocate memory
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy a string
char *safe_strndup(const char *str, size_t n) {
    char *new_str = (char *)safe_malloc(n + 1);
    strncpy(new_str, str, n);
    new_str[n] = '\0';
    return new_str;
}

// Function to safely copy a buffer
void *safe_memcpy(void *dest, const void *src, size_t n) {
    if (dest == NULL || src == NULL) {
        return NULL;
    }
    return memcpy(dest, src, n);
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < sizeof(ares_channel)) {  // Use the complete type name
        return 0;
    }

    // Initialize variables
    ares_channel channel;  // Use the complete type name
    struct ares_addr_port_node *servers_ports = NULL;
    struct ares_addr_node *servers = NULL;
    char *servers_csv = NULL;
    char *expanded_name = NULL;
    unsigned char *expanded_string = NULL;
    long enclen_name = 0, enclen_string = 0;

    // Initialize the channel with dummy data (since we don't have a real channel)
    memset(&channel, 0, sizeof(channel));
    safe_memcpy(&channel, data, sizeof(channel));

    // Call ares_get_servers_ports
    int status = ares_get_servers_ports(&channel, &servers_ports);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_get_servers_csv
    servers_csv = ares_get_servers_csv(&channel);
    if (!servers_csv) {
        goto cleanup;
    }

    // Call ares_get_servers
    status = ares_get_servers(&channel, &servers);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_expand_name
    status = ares_expand_name(data, data, size, &expanded_name, &enclen_name);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Call ares_expand_string
    status = ares_expand_string(data, data, size, &expanded_string, &enclen_string);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

cleanup:
    // Free allocated resources
    if (servers_ports) {
        ares_free_data(servers_ports);
    }
    if (servers) {
        ares_free_data(servers);
    }
    if (servers_csv) {
        ares_free_string(servers_csv);
    }
    if (expanded_name) {
        ares_free_string(expanded_name);
    }
    if (expanded_string) {
        ares_free_string(expanded_string);
    }

    return 0;
}
