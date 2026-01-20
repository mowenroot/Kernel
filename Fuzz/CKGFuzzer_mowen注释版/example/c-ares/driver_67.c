#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static void safe_strncpy(char *dest, const uint8_t *src, size_t n) {
    size_t i;
    for (i = 0; i < n - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Function to safely convert fuzz input to an integer
static int safe_atoi(const uint8_t *data, size_t size) {
    char buf[12]; // Max length for a 32-bit integer in string form
    if (size > sizeof(buf) - 1) {
        size = sizeof(buf) - 1;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';
    return atoi(buf);
}

// Function to safely convert fuzz input to a short integer
static unsigned short safe_atos(const uint8_t *data, size_t size) {
    char buf[7]; // Max length for a 16-bit integer in string form
    if (size > sizeof(buf) - 1) {
        size = sizeof(buf) - 1;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';
    return (unsigned short)atoi(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel_t *channel = NULL;
    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status;
    int timeout_ms;
    unsigned short id, flags;
    ares_dns_opcode_t opcode;
    ares_dns_rcode_t rcode;
    char local_dev_name[256];

    // Ensure we have enough data for basic operations
    if (size < 10) {
        return 0;
    }

    // Initialize the channel
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Extract values from fuzz input
    timeout_ms = safe_atoi(data, 4);
    id = safe_atos(data + 4, 2);
    flags = safe_atos(data + 6, 2);
    opcode = (ares_dns_opcode_t)safe_atos(data + 8, 2);
    rcode = (ares_dns_rcode_t)safe_atos(data + 10, 2);
    safe_strncpy(local_dev_name, data + 12, sizeof(local_dev_name));

    // Call ares_dns_record_create
    status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Call ares_set_local_dev
    ares_set_local_dev(channel, local_dev_name);

    // Call ares_reinit
    status = ares_reinit(channel);
    if (status != ARES_SUCCESS) {
        ares_free(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Call ares_queue_wait_empty
    status = ares_queue_wait_empty(channel, timeout_ms);
    if (status != ARES_SUCCESS && status != ARES_ETIMEOUT) {
        ares_free(dnsrec);
        ares_destroy(channel);
        return 0;
    }

    // Clean up
    ares_free(dnsrec);
    ares_destroy(channel);

    return 0;
}
