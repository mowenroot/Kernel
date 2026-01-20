#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// Function to initialize ares channel
static ares_channel_t* initialize_ares_channel() {
    ares_channel_t* channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "Failed to initialize ares channel: %s\n", ares_strerror(status));
        return NULL;
    }
    return channel;
}

// Function to free ares channel
static void free_ares_channel(ares_channel_t* channel) {
    if (channel) {
        ares_destroy(channel);
    }
}

// Function to parse PTR reply
static int parse_ptr_reply(const uint8_t* data, size_t size, struct hostent** host) {
    int status = ares_parse_ptr_reply(data, size, NULL, 0, AF_INET, host);
    if (status != ARES_SUCCESS) {
        fprintf(stderr, "Failed to parse PTR reply: %s\n", ares_strerror(status));
        return status;
    }
    return ARES_SUCCESS;
}

// Function to free hostent structure
static void free_hostent(struct hostent* host) {
    if (host) {
        ares_free_hostent(host);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t* channel = initialize_ares_channel();
    if (!channel) {
        return 0;
    }

    struct hostent* host = NULL;
    fd_set read_fds, write_fds;
    int nfds;

    // Initialize file descriptor sets
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Parse PTR reply
    int status = parse_ptr_reply(data, size, &host);
    if (status != ARES_SUCCESS) {
        free_ares_channel(channel);
        return 0;
    }

    // Get file descriptors
    nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds < 0) {
        fprintf(stderr, "Failed to get file descriptors\n");
        free_hostent(host);
        free_ares_channel(channel);
        return 0;
    }

    // Process file descriptors
    ares_process(channel, &read_fds, &write_fds);

    // Clean up
    free_hostent(host);
    free_ares_channel(channel);

    return 0;
}
