#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from source to destination with a size limit
static void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest && src && dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

// Function to safely allocate memory and copy data
static void *safe_malloc_and_copy(const void *src, size_t size) {
    if (src && size > 0) {
        void *dest = malloc(size);
        if (dest) {
            memcpy(dest, src, size);
        }
        return dest;
    }
    return NULL;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < sizeof(unsigned int) + 16 + 1 + sizeof(ares_sock_create_callback) + 1) {
        return 0;
    }

    // Initialize variables
    ares_channel_t *channel = NULL;
    struct ares_options options;
    int optmask = 0;
    unsigned int local_ip4;
    unsigned char local_ip6[16];
    char local_dev_name[256];
    ares_sock_create_callback sock_create_cb;
    void *sock_create_cb_data;

    // Extract data from the fuzz input
    local_ip4 = *(unsigned int *)data;
    memcpy(local_ip6, data + sizeof(unsigned int), 16);
    size_t dev_name_len = data[sizeof(unsigned int) + 16];
    if (dev_name_len >= sizeof(local_dev_name)) {
        dev_name_len = sizeof(local_dev_name) - 1;
    }
    safe_strncpy(local_dev_name, (const char *)(data + sizeof(unsigned int) + 16 + 1), dev_name_len);
    sock_create_cb = (ares_sock_create_callback)(data + sizeof(unsigned int) + 16 + 1 + dev_name_len);
    sock_create_cb_data = (void *)(data + sizeof(unsigned int) + 16 + 1 + dev_name_len + sizeof(ares_sock_create_callback));

    // Initialize the channel
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Call the APIs with the extracted data
    ares_set_local_ip4(channel, local_ip4);
    ares_set_local_ip6(channel, local_ip6);
    ares_set_local_dev(channel, local_dev_name);
    ares_set_socket_callback(channel, sock_create_cb, sock_create_cb_data);

    // Save options and handle errors
    status = ares_save_options(channel, &options, &optmask);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Clean up
    ares_destroy_options(&options);
    ares_destroy(channel);

    return 0;
}
