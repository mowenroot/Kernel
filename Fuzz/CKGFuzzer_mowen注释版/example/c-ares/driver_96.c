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

// Function to safely allocate memory for ares_options
static struct ares_options* safe_ares_options_alloc(const uint8_t *data, size_t size) {
    struct ares_options *options = (struct ares_options*)malloc(sizeof(struct ares_options));
    if (!options) return NULL;
    memset(options, 0, sizeof(struct ares_options));

    // Example of setting options fields from fuzz input
    if (size > 0) {
        options->timeout = data[0];
        options->tries = data[1];
    }
    return options;
}

// Function to safely allocate memory for ares_addr_node
static struct ares_addr_node* safe_ares_addr_node_alloc(const uint8_t *data, size_t size) {
    struct ares_addr_node *servers = (struct ares_addr_node*)malloc(sizeof(struct ares_addr_node));
    if (!servers) return NULL;
    memset(servers, 0, sizeof(struct ares_addr_node));

    // Example of setting servers fields from fuzz input
    if (size > 0) {
        servers->family = data[0];
        servers->addr.addr4.s_addr = data[1];
    }
    return servers;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL;
    struct ares_options *options = NULL;
    struct ares_addr_node *servers = NULL;
    int result = 0;

    // Initialize the c-ares library
    result = ares_library_init(ARES_LIB_INIT_ALL);
    if (result != ARES_SUCCESS) {
        return 0;
    }

    // Safely allocate and initialize ares_options
    options = safe_ares_options_alloc(data, size);
    if (!options) {
        ares_library_cleanup();
        return 0;
    }

    // Initialize the channel with options
    result = ares_init_options(&channel, options, ARES_OPT_TIMEOUT | ARES_OPT_TRIES);
    if (result != ARES_SUCCESS) {
        free(options);
        ares_library_cleanup();
        return 0;
    }

    // Safely allocate and initialize ares_addr_node
    servers = safe_ares_addr_node_alloc(data, size);
    if (!servers) {
        ares_destroy(channel);
        free(options);
        ares_library_cleanup();
        return 0;
    }

    // Set the DNS servers for the channel
    result = ares_set_servers(channel, servers);
    if (result != ARES_SUCCESS) {
        ares_destroy(channel);
        free(servers);
        free(options);
        ares_library_cleanup();
        return 0;
    }

    // Clean up resources
    ares_destroy(channel);
    free(servers);
    free(options);
    ares_library_cleanup();

    return 0;
}
