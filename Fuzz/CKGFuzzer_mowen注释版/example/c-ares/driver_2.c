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

// Function to safely allocate and initialize ares_channel_t
static ares_channel_t* safe_ares_channel_init() {
    ares_channel_t *channel = NULL;
    ares_status_t status = ares_init(&channel); // Use ares_init to initialize the channel
    if (status != ARES_SUCCESS) {
        return NULL;
    }
    return channel;
}

// Function to safely allocate and initialize ares_dns_record_t
static ares_dns_record_t* safe_ares_dns_record_init(unsigned short id, unsigned short flags, ares_dns_opcode_t opcode, ares_dns_rcode_t rcode) {
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return NULL;
    }
    return dnsrec;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is sufficient for basic operations
    if (size < sizeof(unsigned short) * 4 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t) + 16) {
        return 0;
    }

    // Extract parameters from fuzz input
    unsigned short id = *(unsigned short*)data;
    unsigned short flags = *(unsigned short*)(data + sizeof(unsigned short));
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t*)(data + sizeof(unsigned short) * 2);
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t*)(data + sizeof(unsigned short) * 2 + sizeof(ares_dns_opcode_t));
    const unsigned char *local_ip6 = data + sizeof(unsigned short) * 4 + sizeof(ares_dns_opcode_t) + sizeof(ares_dns_rcode_t);

    // Initialize ares_channel_t
    ares_channel_t *channel = safe_ares_channel_init();
    if (!channel) {
        return 0;
    }

    // Initialize ares_dns_record_t
    ares_dns_record_t *dnsrec = safe_ares_dns_record_init(id, flags, opcode, rcode);
    if (!dnsrec) {
        ares_destroy(channel); // Use ares_destroy to free the channel
        return 0;
    }

    // Call ares_reinit
    ares_status_t reinit_status = ares_reinit(channel);
    if (reinit_status != ARES_SUCCESS) {
        ares_free(dnsrec);
        ares_destroy(channel); // Use ares_destroy to free the channel
        return 0;
    }

    // Call ares_set_local_ip6
    ares_set_local_ip6(channel, local_ip6);

    // Call ares_gethostbyaddr (dummy callback)
    ares_gethostbyaddr(channel, local_ip6, 16, AF_INET6, NULL, NULL);

    // Free allocated resources
    ares_free(dnsrec);
    ares_destroy(channel); // Use ares_destroy to free the channel

    // Free any dynamically allocated strings
    char *str = safe_strndup(data, size);
    if (str) {
        ares_free_string(str);
    }

    return 0;
}
