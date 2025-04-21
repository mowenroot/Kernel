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

// Function to safely create a channel
ares_channel_t* safe_create_channel() {
    ares_channel_t *channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return NULL;
    }
    return channel;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is sufficient for processing
    if (size < 1) return 0;

    // Initialize variables
    ares_channel_t *channel = safe_create_channel();
    if (!channel) return 0;

    // Extract hostname from fuzz input
    size_t hostname_size = size / 2;
    char *hostname = safe_strndup(data, hostname_size);
    if (!hostname) {
        ares_destroy(channel);
        return 0;
    }

    // Extract timeout value from fuzz input
    int timeout_ms = (int)data[hostname_size];

    // Perform DNS lookup
    ares_gethostbyname(channel, hostname, AF_INET, NULL, NULL);

    // Process the channel
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    ares_process(channel, &read_fds, &write_fds);

    // Wait for the queue to empty with timeout
    ares_status_t status = ares_queue_wait_empty(channel, timeout_ms);
    if (status != ARES_SUCCESS && status != ARES_ETIMEOUT) {
        ares_cancel(channel);
    }

    // Free allocated resources
    ares_free_string(hostname);
    ares_destroy(channel);

    return 0;
}
