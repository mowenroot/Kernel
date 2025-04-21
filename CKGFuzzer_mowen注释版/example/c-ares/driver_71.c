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

// Function to safely allocate memory for a DNS record
static ares_dns_record_t* safe_dns_record_create(const uint8_t *data, size_t size) {
    ares_dns_record_t *dnsrec = NULL;
    unsigned short id = (unsigned short)(data[0] << 8 | data[1]);
    unsigned short flags = (unsigned short)(data[2] << 8 | data[3]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];

    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) {
        return NULL;
    }
    return dnsrec;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6) return 0; // Minimum size for creating a DNS record

    // Initialize ares channel
    ares_channel_t *channel = NULL;
    ares_status_t status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Create a DNS record
    ares_dns_record_t *dnsrec = safe_dns_record_create(data, size);
    if (!dnsrec) {
        ares_destroy(channel);
        return 0;
    }

    // Perform a DNS record search
    ares_search_dnsrec(channel, dnsrec, NULL, NULL);

    // Send a DNS query
    ares_send(channel, data, size, NULL, NULL);

    // Process DNS queries
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    ares_process(channel, &read_fds, &write_fds);

    // Perform a DNS query
    char *name = safe_strndup(data, size);
    if (name) {
        ares_query(channel, name, C_IN, T_A, NULL, NULL);
        free(name);
    }

    // Cleanup
    ares_dns_record_destroy(dnsrec);
    ares_destroy(channel);

    return 0;
}
