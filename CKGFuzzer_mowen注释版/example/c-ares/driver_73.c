#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a CSV string from fuzz input
char* create_csv_string(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *csv = (char*)malloc(size + 1);
    if (!csv) return NULL;
    memcpy(csv, data, size);
    csv[size] = '\0';
    return csv;
}

// Function to safely create an IPv4 address from fuzz input
unsigned int create_ipv4_address(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

// Function to safely create an IPv6 address from fuzz input
void create_ipv6_address(const uint8_t *data, size_t size, unsigned char *ipv6) {
    if (size < 16) return;
    memcpy(ipv6, data, 16);
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel_t *channel;
    ares_status_t status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Safely create CSV string for servers and ports
    char *csv_servers_ports = create_csv_string(data, size);
    if (csv_servers_ports) {
        status = ares_set_servers_ports_csv(channel, csv_servers_ports);
        if (status != ARES_SUCCESS) {
            free(csv_servers_ports);
            ares_destroy(channel);
            return 0;
        }
        free(csv_servers_ports);
    }

    // Safely create sortlist string
    char *sortlist_str = safe_strndup(data, size);
    if (sortlist_str) {
        status = ares_set_sortlist(channel, sortlist_str);
        if (status != ARES_SUCCESS) {
            free(sortlist_str);
            ares_destroy(channel);
            return 0;
        }
        free(sortlist_str);
    }

    // Safely create IPv4 address
    unsigned int local_ip4 = create_ipv4_address(data, size);
    ares_set_local_ip4(channel, local_ip4);

    // Safely create IPv6 address
    unsigned char local_ip6[16];
    create_ipv6_address(data, size, local_ip6);
    ares_set_local_ip6(channel, local_ip6);

    // Clean up
    ares_destroy(channel);
    return 0;
}
