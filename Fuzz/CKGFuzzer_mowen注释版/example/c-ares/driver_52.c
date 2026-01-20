#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static void safe_strncpy(char *dest, const uint8_t *src, size_t n) {
    size_t i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Function to safely allocate memory and copy fuzz input
static void *safe_malloc_and_copy(const uint8_t *data, size_t size) {
    void *ptr = malloc(size);
    if (ptr) {
        memcpy(ptr, data, size);
    }
    return ptr;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(struct sockaddr_in) + 1) {
        return 0;
    }

    // Initialize variables
    ares_channel channel;
    struct hostent *host = NULL;
    struct sockaddr_in sa;
    char local_dev_name[256];
    int status;

    // Initialize the c-ares library
    status = ares_library_initialized();
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Set local device name
    safe_strncpy(local_dev_name, data, sizeof(local_dev_name));
    ares_set_local_dev(&channel, local_dev_name);

    // Prepare sockaddr_in structure
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    memcpy(&sa.sin_addr, data + sizeof(local_dev_name), sizeof(sa.sin_addr));

    // Perform ares_getnameinfo
    ares_getnameinfo(&channel, (struct sockaddr *)&sa, sizeof(sa), 0, NULL, NULL);

    // Parse PTR reply
    status = ares_parse_ptr_reply(data, size, &sa.sin_addr, sizeof(sa.sin_addr), AF_INET, &host);
    if (status != ARES_SUCCESS) {
        ares_free_hostent(host);
        ares_destroy(channel);
        return 0;
    }

    // Cleanup
    ares_free_hostent(host);
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
