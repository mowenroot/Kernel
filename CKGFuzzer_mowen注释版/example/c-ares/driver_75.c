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
    if (size < sizeof(struct ares_addr_node)) return NULL;
    struct ares_addr_node *node = (struct ares_addr_node*)malloc(sizeof(struct ares_addr_node));
    if (!node) return NULL;
    memcpy(node, data, sizeof(struct ares_addr_node));
    return node;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel_t *channel = NULL;
    ares_status_t status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Ensure we have enough data for each API call
    if (size < 100) {
        ares_destroy(channel);
        return 0;
    }

    // ares_set_sortlist
    char *sortlist_str = safe_strndup(data, 20);
    if (sortlist_str) {
        ares_set_sortlist(channel, sortlist_str);
        free(sortlist_str);
    }

    // ares_set_local_ip4
    unsigned int local_ip4 = *(unsigned int*)(data + 20);
    ares_set_local_ip4(channel, local_ip4);

    // ares_set_servers_ports_csv
    char *servers_ports_csv = safe_strndup(data + 24, 20);
    if (servers_ports_csv) {
        ares_set_servers_ports_csv(channel, servers_ports_csv);
        free(servers_ports_csv);
    }

    // ares_set_local_ip6
    const unsigned char *local_ip6 = data + 44;
    ares_set_local_ip6(channel, local_ip6);

    // ares_set_local_dev
    char *local_dev_name = safe_strndup(data + 60, 20);
    if (local_dev_name) {
        ares_set_local_dev(channel, local_dev_name);
        free(local_dev_name);
    }

    // ares_set_servers
    struct ares_addr_node *servers = safe_alloc_addr_node(data + 80, 20);
    if (servers) {
        ares_set_servers(channel, servers);
        free(servers);
    }

    // Clean up
    ares_destroy(channel);
    return 0;
}
