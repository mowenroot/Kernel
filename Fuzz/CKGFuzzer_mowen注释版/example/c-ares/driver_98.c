#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for ares_options
static struct ares_options* safe_ares_options_alloc(const uint8_t *data, size_t size) {
    struct ares_options *options = (struct ares_options*)malloc(sizeof(struct ares_options));
    if (!options) return NULL;
    memset(options, 0, sizeof(struct ares_options));

    // Example of setting options based on fuzz input
    if (size > 0) {
        options->timeout = data[0];
    }
    return options;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ares_channel_t *channel = NULL;
    struct ares_options *options = NULL;
    int optmask = 0;
    int result = 0;

    // Initialize options based on fuzz input
    options = safe_ares_options_alloc(data, size);
    if (!options) {
        return 0; // Early exit if allocation fails
    }

    // Initialize the library with options
    result = ares_init_options(&channel, options, optmask);
    if (result != ARES_SUCCESS) {
        free(options);
        return 0; // Early exit if initialization fails
    }

    // Reinitialize the channel
    ares_reinit(channel);

    // Cleanup the library
    ares_library_cleanup();

    // Free allocated resources
    free(options);
    ares_destroy(channel);

    return 0;
}
