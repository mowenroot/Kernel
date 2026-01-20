#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string with bounds checking
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a uint8_t array to an unsigned int
static unsigned int safe_convert_to_uint(const uint8_t *data, size_t size) {
    unsigned int result = 0;
    for (size_t i = 0; i < size && i < sizeof(unsigned int); i++) {
        result |= (unsigned int)data[i] << (8 * i);
    }
    return result;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel_t *channel = NULL;
    struct ares_soa_reply *soa_reply = NULL;
    struct sockaddr_in sa;
    ares_socklen_t salen = sizeof(sa);
    int flags = 0;
    char *local_dev_name = NULL;
    unsigned int local_ip = 0;

    // Ensure size is sufficient for basic operations
    if (size < sizeof(unsigned int) + 1) {
        return 0;
    }

    // Initialize channel
    ares_init(&channel);
    if (!channel) {
        return 0;
    }

    // Set local IP
    local_ip = safe_convert_to_uint(data, sizeof(unsigned int));
    ares_set_local_ip4(channel, local_ip);

    // Set local device name
    local_dev_name = safe_strndup(data + sizeof(unsigned int), size - sizeof(unsigned int));
    if (local_dev_name) {
        ares_set_local_dev(channel, local_dev_name);
    }

    // Parse SOA reply
    int status = ares_parse_soa_reply(data, size, &soa_reply);
    if (status != ARES_SUCCESS) {
        ares_free_data(soa_reply);
        ares_destroy(channel);
        free(local_dev_name);
        return 0;
    }

    // Perform getnameinfo
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(local_ip);
    ares_getnameinfo(channel, (struct sockaddr*)&sa, salen, flags, NULL, NULL);

    // Clean up
    ares_free_data(soa_reply);
    ares_destroy(channel);
    free(local_dev_name);

    return 0;
}
