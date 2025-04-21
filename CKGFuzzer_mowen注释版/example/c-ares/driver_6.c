#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static void safe_strncpy(char *dest, const uint8_t *src, size_t size, size_t dest_size) {
    size_t len = size < dest_size - 1 ? size : dest_size - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a buffer from fuzz input
static void safe_memcpy(void *dest, const uint8_t *src, size_t size, size_t dest_size) {
    size_t len = size < dest_size ? size : dest_size;
    memcpy(dest, src, len);
}

// Function to safely allocate memory and copy fuzz input
static void *safe_alloc_and_copy(const uint8_t *src, size_t size) {
    void *dest = malloc(size);
    if (dest) {
        memcpy(dest, src, size);
    }
    return dest;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 100) {
        return 0;
    }

    // Initialize variables
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    struct sockaddr_in sa;
    ares_status_t status;

    // Initialize channel
    ares_init(&channel);
    if (!channel) {
        return 0;
    }

    // Set local device name
    char local_dev_name[64];
    safe_strncpy(local_dev_name, data, 64, sizeof(local_dev_name));
    ares_set_local_dev(channel, local_dev_name);

    // Set local IPv6 address
    unsigned char local_ip6[16];
    safe_memcpy(local_ip6, data + 64, 16, sizeof(local_ip6));
    ares_set_local_ip6(channel, local_ip6);

    // Create DNS record
    unsigned short id = (unsigned short)(data[80] << 8 | data[81]);
    unsigned short flags = (unsigned short)(data[82] << 8 | data[83]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[84];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[85];
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Perform getnameinfo
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = *(uint32_t *)(data + 86);
    ares_getnameinfo(channel, (struct sockaddr *)&sa, sizeof(sa), 0, NULL, NULL);

    // Wait for queue to be empty
    int timeout_ms = (int)(data[90] << 24 | data[91] << 16 | data[92] << 8 | data[93]);
    status = ares_queue_wait_empty(channel, timeout_ms);
    if (status != ARES_SUCCESS && status != ARES_ETIMEOUT) {
        ares_destroy(channel);
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    // Clean up
    ares_destroy(channel);
    ares_dns_record_destroy(dnsrec);

    return 0;
}
