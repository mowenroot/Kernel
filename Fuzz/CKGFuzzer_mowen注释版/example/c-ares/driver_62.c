#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h> // Include netdb.h to get the complete definition of struct hostent

// Callback function for ares_query
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    if (status != ARES_SUCCESS) {
        // Handle error
        return;
    }

    struct hostent *host = NULL;
    int parse_status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
    if (parse_status != ARES_SUCCESS) {
        // Handle error
        return;
    }

    // Use host information
    if (host->h_name) {
        // Process host name
        ares_free_string(host->h_name);
    }

    // Free host structure
    ares_free_hostent(host);
}

// Callback function for ares_getnameinfo
void nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
    if (status != ARES_SUCCESS) {
        // Handle error
        return;
    }

    // Use node and service information
    if (node) {
        // Process node name
        ares_free_string(node);
    }
    if (service) {
        // Process service name
        ares_free_string(service);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel channel;
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Ensure data is null-terminated for string operations
    char *name = (char *)malloc(size + 1);
    if (!name) {
        ares_destroy(channel);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Perform ares_query
    ares_query(&channel, name, C_IN, T_PTR, query_callback, NULL);

    // Perform ares_getnameinfo
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = *(uint32_t *)data; // Use first 4 bytes of data as IP address
    ares_getnameinfo(&channel, (struct sockaddr *)&sa, sizeof(sa), 0, nameinfo_callback, NULL);

    // Process pending queries
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    ares_process(&channel, &read_fds, &write_fds);

    // Clean up
    free(name);
    ares_destroy(channel);

    return 0;
}
