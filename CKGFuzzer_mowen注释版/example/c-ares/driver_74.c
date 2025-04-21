#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function prototype for the socket configuration callback
void socket_config_callback(void *data, int s, int read, int write) {
    // Dummy implementation
}

// Function prototype for the socket creation callback
void socket_create_callback(void *data, int s, int read, int write) {
    // Dummy implementation
}

// Function to convert fuzz input to a CSV string
char* create_csv_string(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *csv = (char*)malloc(size + 1);
    if (!csv) return NULL;
    memcpy(csv, data, size);
    csv[size] = '\0';
    return csv;
}

// Function to create a dummy ares_addr_node structure
struct ares_addr_node* create_dummy_servers(const uint8_t *data, size_t size) {
    if (size < sizeof(struct ares_addr_node)) return NULL;
    struct ares_addr_node *servers = (struct ares_addr_node*)malloc(sizeof(struct ares_addr_node));
    if (!servers) return NULL;
    memcpy(&servers->addr, data, sizeof(servers->addr));
    servers->next = NULL;
    return servers;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel_t *channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Set socket configure callback
    ares_set_socket_configure_callback(channel, socket_config_callback, NULL);

    // Set local IPv4 address
    if (size >= sizeof(unsigned int)) {
        unsigned int local_ip;
        memcpy(&local_ip, data, sizeof(unsigned int));
        ares_set_local_ip4(channel, local_ip);
    }

    // Set servers and ports from CSV
    char *csv = create_csv_string(data, size);
    if (csv) {
        ares_set_servers_ports_csv(channel, csv);
        free(csv);
    }

    // Set local device name
    if (size > 0) {
        char local_dev_name[256];
        size_t dev_name_size = size < 255 ? size : 255;
        memcpy(local_dev_name, data, dev_name_size);
        local_dev_name[dev_name_size] = '\0';
        ares_set_local_dev(channel, local_dev_name);
    }

    // Set socket creation callback
    ares_set_socket_callback(channel, socket_create_callback, NULL);

    // Set servers
    struct ares_addr_node *servers = create_dummy_servers(data, size);
    if (servers) {
        ares_set_servers(channel, servers);
        free(servers);
    }

    // Cleanup
    ares_destroy(channel);

    return 0;
}
