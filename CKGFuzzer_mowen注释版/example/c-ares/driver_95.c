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

// Function to safely allocate and initialize a sockaddr_in structure
static struct sockaddr_in* safe_sockaddr_in_create(const uint8_t* data, size_t size) {
    if (size < sizeof(struct sockaddr_in)) return NULL;
    struct sockaddr_in* sa = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if (!sa) return NULL;
    memcpy(sa, data, sizeof(struct sockaddr_in));
    return sa;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel_t* channel = NULL;
    ares_dns_record_t* dnsrec = NULL;
    struct ares_soa_reply* soa_reply = NULL;
    struct sockaddr_in* sa = NULL;
    char* local_dev_name = NULL;
    int status;

    // Initialize the c-ares channel
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        goto cleanup;
    }

    // Set local device name
    if (size > 0) {
        local_dev_name = safe_strndup(data, size);
        if (local_dev_name) {
            ares_set_local_dev(channel, local_dev_name);
        }
    }

    // Create a DNS record
    if (size >= 8) {
        uint16_t id = (uint16_t)(data[0] | (data[1] << 8));
        uint16_t flags = (uint16_t)(data[2] | (data[3] << 8));
        ares_dns_opcode_t opcode = (ares_dns_opcode_t)(data[4]);
        ares_dns_rcode_t rcode = (ares_dns_rcode_t)(data[5]);
        status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

    // Parse SOA reply
    if (size >= sizeof(struct ares_soa_reply)) {
        status = ares_parse_soa_reply(data, (int)size, &soa_reply);
        if (status != ARES_SUCCESS) {
            goto cleanup;
        }
    }

    // Perform nameinfo lookup
    if (size >= sizeof(struct sockaddr_in)) {
        sa = safe_sockaddr_in_create(data, size);
        if (sa) {
            ares_getnameinfo(channel, (struct sockaddr*)sa, sizeof(struct sockaddr_in), 0, NULL, NULL);
        }
    }

cleanup:
    // Free allocated resources
    if (soa_reply) {
        ares_free_data(soa_reply);
    }
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
    if (sa) {
        free(sa);
    }
    if (local_dev_name) {
        free(local_dev_name);
    }
    if (channel) {
        ares_destroy(channel);
    }

    return 0;
}
