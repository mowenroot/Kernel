#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
static int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Function to safely convert fuzz input to a socket address
static struct sockaddr* safe_sockaddr(const uint8_t* data, size_t size) {
    if (size < sizeof(struct sockaddr)) return NULL;
    struct sockaddr* sa = (struct sockaddr*)malloc(sizeof(struct sockaddr));
    if (!sa) return NULL;
    memcpy(sa, data, sizeof(struct sockaddr));
    return sa;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel channel;
    struct ares_soa_reply* soa_reply = NULL;
    struct sockaddr* sa = NULL;
    char* local_dev_name = NULL;
    int status;

    // Initialize the channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Set local device name
    local_dev_name = safe_strndup(data, size);
    if (local_dev_name) {
        ares_set_local_dev(&channel, local_dev_name);
        free(local_dev_name);
    }

    // Parse SOA reply
    status = ares_parse_soa_reply(data, (int)size, &soa_reply);
    if (status != ARES_SUCCESS) {
        ares_free_data(soa_reply);
        ares_destroy(channel);
        return 0;
    }

    // Wait for queue to be empty
    status = ares_queue_wait_empty(&channel, safe_atoi(data, size));
    if (status != ARES_SUCCESS) {
        ares_free_data(soa_reply);
        ares_destroy(channel);
        return 0;
    }

    // Get name info
    sa = safe_sockaddr(data, size);
    if (sa) {
        ares_getnameinfo(&channel, sa, sizeof(struct sockaddr), 0, NULL, NULL);
        free(sa);
    }

    // Perform search
    ares_search(&channel, (const char*)data, ns_c_in, ns_t_a, NULL, NULL);

    // Clean up
    ares_free_data(soa_reply);
    ares_destroy(channel);

    return 0;
}
