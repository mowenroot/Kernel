#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string with bounds checking
char* safe_strndup(const char* str, size_t n) {
    if (str == NULL) return NULL;
    size_t len = strnlen(str, n);
    char* new_str = (char*)malloc(len + 1);
    if (new_str == NULL) return NULL;
    memcpy(new_str, str, len);
    new_str[len] = '\0';
    return new_str;
}

// Function to safely allocate memory for a string with bounds checking
char* safe_strndup_from_data(const uint8_t* data, size_t size) {
    if (data == NULL || size == 0) return NULL;
    return safe_strndup((const char*)data, size);
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL; // Change to pointer type
    struct ares_addr_port_node *servers_ports = NULL;
    struct ares_addr_node *servers = NULL;
    char *servers_csv = NULL;
    char *input_csv = NULL;
    int result;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Test ares_get_servers_ports
    result = ares_get_servers_ports(channel, &servers_ports);
    if (result != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }
    ares_free_data(servers_ports);

    // Test ares_get_servers_csv
    servers_csv = ares_get_servers_csv(channel);
    if (servers_csv) {
        free(servers_csv);
    }

    // Test ares_get_servers
    result = ares_get_servers(channel, &servers);
    if (result != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }
    ares_free_data(servers);

    // Test ares_set_servers_ports_csv
    input_csv = safe_strndup_from_data(data, size);
    if (input_csv) {
        result = ares_set_servers_ports_csv(channel, input_csv);
        free(input_csv);
        if (result != ARES_SUCCESS) {
            ares_destroy(channel);
            return 0;
        }
    }

    // Test ares_set_servers
    // Create a dummy ares_addr_node for testing
    struct ares_addr_node dummy_server;
    dummy_server.family = AF_INET;
    dummy_server.addr.addr4.s_addr = htonl(INADDR_LOOPBACK);
    dummy_server.next = NULL;

    result = ares_set_servers(channel, &dummy_server);
    if (result != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Clean up
    ares_destroy(channel);
    return 0;
}
