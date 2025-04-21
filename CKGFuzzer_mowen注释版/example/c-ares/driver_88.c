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

// Function to safely allocate memory for ares_addr_node
static struct ares_addr_node* safe_alloc_addr_node(const uint8_t *data, size_t size) {
    struct ares_addr_node *node = (struct ares_addr_node*)malloc(sizeof(struct ares_addr_node));
    if (!node) return NULL;
    memset(node, 0, sizeof(struct ares_addr_node));
    if (size >= sizeof(struct in_addr)) {
        node->family = AF_INET;
        memcpy(&node->addr.addr4, data, sizeof(struct in_addr));
    } else if (size >= sizeof(struct in6_addr)) {
        node->family = AF_INET6;
        memcpy(&node->addr.addr6, data, sizeof(struct in6_addr));
    } else {
        free(node);
        return NULL;
    }
    return node;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel channel;
    int status;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // ares_set_servers_ports_csv
    char *csv = safe_strndup(data, size);
    if (csv) {
        status = ares_set_servers_ports_csv(&channel, csv);
        if (status != ARES_SUCCESS) {
            free(csv);
            ares_destroy(channel);
            return 0;
        }
        free(csv);
    }

    // ares_get_servers_ports
    struct ares_addr_port_node *servers_ports = NULL;
    status = ares_get_servers_ports(&channel, &servers_ports);
    if (status == ARES_SUCCESS) {
        ares_free_data(servers_ports);
    }

    // ares_get_servers_csv
    char *servers_csv = ares_get_servers_csv(&channel);
    if (servers_csv) {
        free(servers_csv);
    }

    // ares_get_servers
    struct ares_addr_node *servers = NULL;
    status = ares_get_servers(&channel, &servers);
    if (status == ARES_SUCCESS) {
        ares_free_data(servers);
    }

    // ares_set_servers
    struct ares_addr_node *new_servers = safe_alloc_addr_node(data, size);
    if (new_servers) {
        status = ares_set_servers(&channel, new_servers);
        if (status == ARES_SUCCESS) {
            ares_free_data(new_servers);
        }
    }

    // ares_getaddrinfo
    struct ares_addrinfo_hints hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = ARES_AI_CANONNAME;
    ares_getaddrinfo(&channel, (const char*)data, NULL, &hints, NULL, NULL);

    // Cleanup
    ares_destroy(channel);
    return 0;
}
