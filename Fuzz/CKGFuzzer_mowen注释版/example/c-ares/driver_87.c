#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// Function to initialize the ares channel
ares_channel_t* initialize_ares_channel() {
    ares_channel_t* channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "Failed to initialize ares channel: %s\n", ares_strerror(status));
        return NULL;
    }
    return channel;
}

// Function to free the ares channel
void free_ares_channel(ares_channel_t* channel) {
    if (channel) {
        ares_destroy(channel);
    }
}

// Function to create a sockaddr_in structure from the fuzz input
struct sockaddr_in create_sockaddr_in(const uint8_t* data, size_t size) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (size >= sizeof(sa.sin_addr.s_addr)) {
        memcpy(&sa.sin_addr.s_addr, data, sizeof(sa.sin_addr.s_addr));
    }
    return sa;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize ares channel
    ares_channel_t* channel = initialize_ares_channel();
    if (!channel) {
        return 0;
    }

    // Create sockaddr_in structure from fuzz input
    struct sockaddr_in sa = create_sockaddr_in(data, size);

    // Prepare fd_set for ares_fds and ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Call ares_fds to populate read_fds and write_fds
    int nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds < 0) {
        fprintf(stderr, "ares_fds failed\n");
        free_ares_channel(channel);
        return 0;
    }

    // Call ares_process to handle I/O operations
    ares_process(channel, &read_fds, &write_fds);

    // Call ares_getnameinfo to resolve the address
    ares_getnameinfo(channel, (struct sockaddr*)&sa, sizeof(sa), 0, NULL, NULL);

    // Allocate memory for ares_addrinfo structure
    struct ares_addrinfo* ai = (struct ares_addrinfo*)malloc(sizeof(struct ares_addrinfo));
    if (ai) {
        // Call ares_freeaddrinfo to free the allocated memory
        ares_freeaddrinfo(ai);
    }

    // Cleanup the ares library
    ares_library_cleanup();

    // Free the ares channel
    free_ares_channel(channel);

    return 0;
}
