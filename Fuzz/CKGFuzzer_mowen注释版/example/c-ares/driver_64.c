#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include stdio.h for stderr

// Function to safely copy a string with bounds checking
void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// Function to safely allocate memory and handle errors
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void *ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < sizeof(unsigned int) + 16 + 1 + 1 + sizeof(ares_sock_create_callback)) {
        return 0;
    }

    // Initialize the ares channel
    ares_channel channel;  // Use ares_channel instead of ares_channel_t
    int init_status = ares_init(&channel);  // Renamed 'status' to 'init_status' to avoid redefinition
    if (init_status != ARES_SUCCESS) {
        return 0;
    }

    // Extract data for API calls
    unsigned int local_ip4 = *((unsigned int *)data);
    const unsigned char *local_ip6 = (const unsigned char *)(data + sizeof(unsigned int));
    const char *local_dev_name = (const char *)(data + sizeof(unsigned int) + 16);
    int timeout_ms = (int)(data[sizeof(unsigned int) + 16]);
    ares_sock_create_callback sock_create_cb = (ares_sock_create_callback)(data + sizeof(unsigned int) + 16 + 1);
    void *sock_create_cb_data = (void *)(data + sizeof(unsigned int) + 16 + 1 + sizeof(ares_sock_create_callback));

    // Set local IPv4 address
    ares_set_local_ip4(channel, local_ip4);

    // Set local IPv6 address
    ares_set_local_ip6(channel, local_ip6);

    // Set local device name
    char local_dev_name_buf[256];
    safe_strncpy(local_dev_name_buf, local_dev_name, sizeof(local_dev_name_buf));
    ares_set_local_dev(channel, local_dev_name_buf);

    // Set socket callback
    ares_set_socket_callback(channel, sock_create_cb, sock_create_cb_data);

    // Wait for the queue to be empty with a timeout
    ares_status_t queue_status = ares_queue_wait_empty(channel, timeout_ms);  // Renamed 'status' to 'queue_status' to avoid redefinition
    if (queue_status != ARES_SUCCESS && queue_status != ARES_ETIMEOUT) {
        fprintf(stderr, "ares_queue_wait_empty failed with status: %d\n", queue_status);
    }

    // Get the number of active queries
    size_t active_queries = ares_queue_active_queries(channel);
    if (active_queries > 0) {
        fprintf(stderr, "Unexpected number of active queries: %zu\n", active_queries);
    }

    // Clean up
    ares_destroy(channel);

    return 0;
}
